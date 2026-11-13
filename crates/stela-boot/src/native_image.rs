//! Original allocation owner of the relocated, statically linked engine image.
//! Range observations and read-only data classifiers cannot construct this pin.
use crate::{
    handoff::{Handoff, Region},
    layout,
};
use stela_boot_core::{pe, resident_image::Layout};

pub(crate) enum Error {
    Allocation(uefi::Status),
    Geometry(stela_boot_core::resident_image::Error),
    Overflow,
    ForeignHandoff,
    ExposedAllocation,
    Header(crate::Refusal),
    ForeignCode,
    ForeignData,
    NotLoaderData,
}
impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Allocation(status) => f.debug_tuple("Allocation").field(status).finish(),
            Self::Geometry(error) => f.debug_tuple("Geometry").field(error).finish(),
            Self::Header(error) => f.debug_tuple("Header").field(error).finish(),
            Self::Overflow => f.write_str("Overflow"),
            Self::ForeignHandoff => f.write_str("ForeignHandoff"),
            Self::ExposedAllocation => f.write_str("ExposedAllocation"),
            Self::ForeignCode => f.write_str("ForeignCode"),
            Self::ForeignData => f.write_str("ForeignData"),
            Self::NotLoaderData => f.write_str("NotLoaderData"),
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "resident kernel image: {self:?}")
    }
}

/// Created only by the successful UEFI allocation below. No public raw-range
/// constructor, Clone, free or retarget operation exists. The complete allocation,
/// including alignment padding, remains LoaderData for the whole boot.
struct Allocation {
    physical: u64,
    bytes: u64,
}

pub(crate) struct ResidentImage {
    _allocation: Allocation,
    geometry: Layout,
    image_bytes: usize,
}
const ALIGNMENT: u64 = 2 * 1024 * 1024;

impl ResidentImage {
    /// The firmware bytes [`Self::allocate`] takes for an image of
    /// `image_bytes`: room to place it on a 2 MiB boundary.
    pub(crate) const fn allocation_bytes(image_bytes: usize) -> u64 {
        (image_bytes as u64 + ALIGNMENT).next_multiple_of(4096)
    }

    pub(crate) fn allocate(image_bytes: usize, virtual_base: u64) -> Result<Self, Error> {
        if image_bytes == 0
            || image_bytes > isize::MAX as usize
            || !virtual_base.is_multiple_of(4096)
        {
            return Err(Error::Geometry(
                stela_boot_core::resident_image::Error::Geometry,
            ));
        }
        let bytes = (image_bytes as u64)
            .checked_add(ALIGNMENT)
            .and_then(|bytes| bytes.checked_next_multiple_of(4096))
            .ok_or(Error::Overflow)?;
        let pages = usize::try_from(bytes / 4096).map_err(|_| Error::Overflow)?;
        let page =
            crate::firmware::any_pages(pages).map_err(|error| Error::Allocation(error.status()))?;
        // SAFETY: successful fresh firmware allocation owns exactly bytes;
        // zero padding before copying prevents exposing former RAM contents.
        unsafe { page.as_ptr().write_bytes(0, bytes as usize) };
        let allocation = Allocation {
            physical: page.as_ptr() as u64,
            bytes,
        };
        let geometry = Layout::within(
            allocation.physical
                ..allocation
                    .physical
                    .checked_add(allocation.bytes)
                    .ok_or(Error::Overflow)?,
            image_bytes,
            ALIGNMENT,
            virtual_base,
        )
        .map_err(Error::Geometry)?;
        Ok(Self {
            _allocation: allocation,
            geometry,
            image_bytes,
        })
    }
    /// Observation only, used to copy/relocate/map this same owned allocation.
    pub(crate) fn region(&self) -> Region {
        let span = self.geometry.physical();
        Region {
            physical: span.start,
            bytes: span.end - span.start,
        }
    }
    pub(crate) fn allocation_region(&self) -> Region {
        Region {
            physical: self._allocation.physical,
            bytes: self._allocation.bytes,
        }
    }
    /// Pin the same original allocation under the final immutable handoff.
    ///
    /// # Safety
    /// On the validated actual CPU under an owned native root. Its real kept
    /// RootIdentity/LoaderTables graph maps this exact original copied PE at
    /// its geometry virtual alias with the original PE section permissions.
    /// Its retained WB physical observation alias may be privileged RW/NX;
    /// exclusive allocation custody forbids mutation through that alias after
    /// relocation of headers, code or immutable DATA. No patcher, DMA/guest
    /// loan, allocator reuse or root writer changes those bytes or this epoch.
    /// The root may be the original loader root or its actually owned shared
    /// native projection. Numeric CR3/ranges alone are insufficient; this pin
    /// conveys allocation custody, never CPU/root/cache access permission.
    /// The final guest inventory excludes all LoaderCode/LoaderData allocations.
    pub(crate) unsafe fn pin(&'static self, handoff: &'static Handoff) -> Result<CodePin, Error> {
        if !core::ptr::eq(self, &handoff.native_image)
            || self.geometry.virtual_range().start != layout::image()
            || handoff.guest_count > handoff.guest.len()
        {
            return Err(Error::ForeignHandoff);
        }
        let regions = handoff.guest[..handoff.guest_count].iter().chain([
            &handoff.heap,
            &handoff.stack,
            &handoff.code,
            &handoff.pool,
            &handoff.native_resources.tasks,
        ]);
        for region in regions {
            let end = region
                .physical
                .checked_add(region.bytes)
                .ok_or(Error::Overflow)?;
            if region.bytes != 0 && self.geometry.overlaps(region.physical..end) {
                return Err(Error::ExposedAllocation);
            }
        }
        Ok(CodePin { image: self })
    }
}

/// Retains the original allocation object in the same never-freed handoff.
/// The queue separately keeps the exact loader/root mappings and CPU owner.
#[derive(Clone)]
pub(crate) struct CodePin {
    image: &'static ResidentImage,
}
impl CodePin {
    /// Original immutable, non-executable PE sections, observed under the same
    /// kept native root. These observations alone never create code authority.
    ///
    /// # Safety
    /// Same original immutable-header/root contract as check_callback.
    pub(crate) unsafe fn readonly_ranges(
        &self,
    ) -> Result<alloc::vec::Vec<core::ops::Range<usize>>, Error> {
        let physical = self.image.geometry.physical().start;
        let base = layout::physical(physical) as *const u8;
        let sections = pe::sections(self.image.image_bytes, |offset, out| {
            // SAFETY: the parser bounds every read within this same real image.
            unsafe {
                core::ptr::copy_nonoverlapping(base.add(offset), out.as_mut_ptr(), out.len())
            };
        })
        .map_err(Error::Header)?;
        let virtual_base = self.image.geometry.virtual_range().start as usize;
        Ok(sections
            .into_iter()
            .filter(|section| !section.writable && !section.executable)
            .map(|section| (virtual_base + section.first)..(virtual_base + section.end))
            .collect())
    }
    /// Writable non-executable payload ranges in the actual relocated image.
    /// Each item pairs the CPU span with the corresponding original physical
    /// start. Section padding supplies no storage membership.
    ///
    /// # Safety
    /// Same original immutable-header/root contract as check_callback.
    pub(crate) unsafe fn writable_data_ranges(
        &self,
    ) -> Result<alloc::vec::Vec<(core::ops::Range<usize>, u64)>, Error> {
        let physical = self.image.geometry.physical().start;
        let base = layout::physical(physical) as *const u8;
        let virtual_base = self.image.geometry.virtual_range().start as usize;
        let mut ranges = alloc::vec::Vec::new();
        pe::visit_sections(
            self.image.image_bytes,
            |offset, out| {
                // SAFETY: parser-bounded header reads in the kept allocation.
                unsafe {
                    core::ptr::copy_nonoverlapping(base.add(offset), out.as_mut_ptr(), out.len())
                };
            },
            |section, payload_end| {
                if section.writable && !section.executable {
                    ranges.push((
                        virtual_base + section.first..virtual_base + payload_end,
                        physical + section.first as u64,
                    ));
                }
            },
        )
        .map_err(Error::Header)?;
        Ok(ranges)
    }
    /// Return the original physical byte of a callback in executable PE payload.
    ///
    /// # Safety
    /// Same kept original CPU/root/immutable-header contract as ResidentImage::pin.
    pub(crate) unsafe fn check_callback(&self, address: usize) -> Result<u64, Error> {
        // SAFETY: the caller holds the original image and root contract.
        unsafe {
            self.section_physical(address, 1, |section| section.executable, Error::ForeignCode)
        }
    }
    /// Return the original physical start of a complete writable PE payload span.
    ///
    /// # Safety
    /// Same kept original CPU/root/immutable-header contract as ResidentImage::pin.
    pub(crate) unsafe fn writable_span(&self, address: usize, bytes: usize) -> Result<u64, Error> {
        // SAFETY: the caller holds the original image and root contract.
        unsafe {
            self.section_physical(
                address,
                bytes,
                |section| section.writable,
                Error::ForeignData,
            )
        }
    }
    unsafe fn section_physical(
        &self,
        address: usize,
        bytes: usize,
        accepts: impl Fn(pe::Section) -> bool,
        foreign: Error,
    ) -> Result<u64, Error> {
        let virtual_base = self.image.geometry.virtual_range().start as usize;
        let Some(offset) = address.checked_sub(virtual_base) else {
            return Err(foreign);
        };
        let Some(end) = offset.checked_add(bytes) else {
            return Err(foreign);
        };
        if offset == end || end > self.image.image_bytes {
            return Err(foreign);
        }
        let physical = self.image.geometry.physical().start;
        let base = layout::physical(physical) as *const u8;
        let mut matches = false;
        pe::visit_sections(
            self.image.image_bytes,
            |offset, out| {
                // SAFETY: the parser bounds each read within the exact
                // original image allocation, without borrowing writable statics.
                unsafe {
                    core::ptr::copy_nonoverlapping(base.add(offset), out.as_mut_ptr(), out.len())
                };
            },
            |section, payload_end| {
                matches |= section.first <= offset && end <= payload_end && accepts(section);
            },
        )
        .map_err(Error::Header)?;
        if !matches {
            return Err(foreign);
        }
        physical.checked_add(offset as u64).ok_or(Error::Overflow)
    }
}
