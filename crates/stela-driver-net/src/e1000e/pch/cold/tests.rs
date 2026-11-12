extern crate std;
use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec};
use core::sync::atomic::{AtomicUsize, Ordering};

pub(super) struct Model {
    pub(super) timing_failure: Option<crate::bus::pci::power::Error>,
    pub(super) fail_delay_at: Option<usize>,
    pub(super) delay_calls: usize,
    pub(super) timer_drops: Arc<AtomicUsize>,

    pub(super) mac: BTreeMap<u32, u32>,
    pub(super) config: BTreeMap<u16, u16>,
    pub(super) spt: bool,
    pub(super) power_busy: usize,
    pub(super) power_pending: bool,
    pub(super) power_stuck: bool,
    pub(super) smb_hidden_after_power: bool,
    pub(super) smb_hidden: bool,
    pub(super) smb_stuck: bool,
    pub(super) ulp_stuck: bool,
    /// A PHY in ULP or behind SMBus: no MDIO cycle completes until the
    /// LANPHYPC toggle brings it back.
    pub(super) phy_asleep: bool,
    /// An Intel ME that never finishes taking the PHY out of ULP.
    pub(super) me_stuck: bool,
    pub(super) flush_after_tx: bool,
    pub(super) flush_after_rx: bool,
    pub(super) phy: BTreeMap<(u8, u16, u16), u16>,
    pub(super) emi: BTreeMap<u16, u16>,
    pub(super) kmrn: BTreeMap<u8, u16>,
    pub(super) words: Vec<u16>,
    pub(super) operations: Vec<[u32; 3]>,
    pub(super) accesses: usize,
    pub(super) fail_at: Option<usize>,
    pub(super) fail_with: Fault,
    pub(super) page: u16,
    pub(super) emi_address: u16,
    pub(super) flash_address: u32,
    pub(super) flash_control: u16,
    pub(super) time: u64,
    pub(super) quiet_until: u64,
    /// The Intel ME holds the PHY semaphore until this model time.
    pub(super) firmware_flag_until: u64,
    /// Each MDIO cycle takes this long before MDIC reports it ready.
    pub(super) mdic_cycle_us: u64,
    pub(super) mdic_ready_at: u64,
    pub(super) master_busy: usize,
    pub(super) mdic_failures: usize,
    /// The MDIC attempt the `mdic_failures` window starts at.
    pub(super) mdic_fail_after: usize,
    pub(super) mdic_attempts: usize,
    pub(super) mdic_kind: u8,
    pub(super) init_missing: bool,
    pub(super) reset_missing: bool,
    pub(super) reset_stuck: bool,
}
impl Model {
    fn ready() -> Self {
        let mut words = vec![0; 4096];
        words[0] = 0x1102;
        words[1] = 0x3322;
        words[2] = 0x5544;
        words[0x13] = 0x8000;
        words[0x19] = 0x40;
        let sum = words[..63].iter().copied().fold(0u16, u16::wrapping_add);
        words[63] = 0xbabau16.wrapping_sub(sum);
        // LCD: page769, indexed data; then page772 and another value.
        words[128..136].copy_from_slice(&[769 << 5, 31, 0x125a, 20, 772 << 5, 31, 0x5601, 21]);
        Self {
            timing_failure: None,
            fail_delay_at: None,
            delay_calls: 0,
            timer_drops: Arc::new(AtomicUsize::new(0)),
            mac: BTreeMap::from([
                (super::super::FWSM, super::super::RESET_PERMITTED),
                (super::super::EXTCNF_CTRL, 64 << 16),
                (EXTCNF_SIZE, 4 << 16),
                (FEXTNVM, SW_CONFIG),
                (STRAP, 0x55 << 17),
                (LEDCTL, 0xa5c7),
                (PHY_CTRL, PHY_D0_LPLU),
                (0x1000, (6 << 16) | 26),
            ]),
            config: BTreeMap::from([(0xa8, 0x1003), (0xaa, 0x1003), (0xe4, 0)]),
            spt: false,
            power_busy: 0,
            power_pending: false,
            power_stuck: false,
            smb_hidden_after_power: false,
            smb_hidden: false,
            smb_stuck: false,
            ulp_stuck: false,
            phy_asleep: false,
            me_stuck: false,
            flush_after_tx: false,
            flush_after_rx: false,
            phy: BTreeMap::from([((2, 0, 2), 0x154), ((2, 0, 3), 0x93)]),
            emi: BTreeMap::new(),
            kmrn: BTreeMap::new(),
            words,
            operations: Vec::new(),
            accesses: 0,
            fail_at: None,
            fail_with: Fault::Access,
            page: 0,
            emi_address: 0,
            flash_address: 0,
            flash_control: 0,
            time: 0,
            quiet_until: 0,
            firmware_flag_until: 0,
            mdic_cycle_us: 0,
            mdic_ready_at: 0,
            master_busy: 0,
            mdic_failures: 0,
            mdic_fail_after: 0,
            mdic_attempts: 0,
            mdic_kind: 0,
            init_missing: false,
            reset_missing: false,
            reset_stuck: false,
        }
    }
    fn enter(&mut self) -> Result<(), Fault> {
        assert!(
            self.time >= self.quiet_until,
            "forbidden access immediately after reset"
        );
        let at = self.accesses;
        self.accesses += 1;
        if self.fail_at == Some(at) {
            Err(self.fail_with)
        } else {
            Ok(())
        }
    }
    fn phy_load(&self, address: u8, index: u16) -> u16 {
        let page = if index <= 15 { 0 } else { self.page };
        if address == 2 && page == 0 && index == 17 {
            return self.emi.get(&self.emi_address).copied().unwrap_or(0);
        }
        self.phy.get(&(address, page, index)).copied().unwrap_or(0)
    }
    fn phy_store(&mut self, address: u8, index: u16, value: u16) {
        if index == 31 {
            self.page = value >> 5;
            return;
        }
        let page = if index <= 15 { 0 } else { self.page };
        if address == 2 && page == 0 && index == 16 {
            self.emi_address = value;
        } else if address == 2 && page == 0 && index == 17 {
            self.emi.insert(self.emi_address, value);
        } else {
            if self.spt
                && ((self.ulp_stuck && page == 779 && index == 16)
                    || (self.smb_stuck && page == 769 && index == 23))
            {
                return;
            }
            self.phy.insert((address, page, index), value);
        }
    }
    fn did_reset(&mut self) {
        let status = if self.init_missing { 0 } else { INIT_DONE }
            | if self.reset_missing {
                0
            } else {
                PHY_RESET_ASSERTED
            };
        self.mac.insert(STATUS, status);
        self.page = 0;
    }
}
pub(super) struct Io(Rc<RefCell<Model>>, Arc<AtomicUsize>);
impl Drop for Io {
    fn drop(&mut self) {
        self.1.fetch_add(1, Ordering::SeqCst);
    }
}
// SAFETY: exclusively serialized model, no resources or hardware.
unsafe impl Registers for Io {
    fn read32(&mut self, at: u32) -> Result<u32, Fault> {
        let mut m = self.0.borrow_mut();
        m.enter()?;
        let mut value = m.mac.get(&at).copied().unwrap_or(0);
        if at == super::super::EXTCNF_CTRL && m.time < m.firmware_flag_until {
            value |= super::super::SWFLAG;
        }
        if at == super::super::MDIC && m.time < m.mdic_ready_at {
            value &= !super::super::MDIC_READY;
        }
        if at == STATUS && m.master_busy != 0 {
            m.master_busy -= 1;
            value |= MASTER_ENABLED;
        }
        if m.spt && at == 0x18 && m.power_pending {
            if m.power_busy == 0 && !m.power_stuck {
                value |= 4;
                m.mac.insert(at, value);
                m.power_pending = false;
            } else {
                m.power_busy = m.power_busy.saturating_sub(1);
                value &= !4;
            }
        }
        m.operations.push([0, at, value]);
        if at == ICR {
            m.mac.insert(at, 0);
        }
        Ok(value)
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Fault> {
        let mut m = self.0.borrow_mut();
        m.enter()?;
        // The integrated PCH MAC has 32 MTA words, not the discrete MAC's
        // 128-word table. Reject the remaining pre-RAR register span so
        // packet initialization cannot silently write reserved addresses.
        if (0x5280..0x5400).contains(&at) {
            return Err(Fault::OutsideBar);
        }
        m.operations.push([1, at, value]);
        let previous = m.mac.get(&at).copied().unwrap_or(0);
        if at == CTRL && value & RESET != 0 {
            m.did_reset();
            let ext = m.mac.get(&super::super::EXTCNF_CTRL).copied().unwrap_or(0);
            m.mac
                .insert(super::super::EXTCNF_CTRL, ext & !super::super::SWFLAG);
            let reset = if m.reset_stuck { RESET } else { 0 };
            m.mac.insert(CTRL, (value & !(RESET | PHY_RESET)) | reset);
            m.quiet_until = m.time + 20_000;
        } else if at == CTRL && previous & PHY_RESET != 0 && value & PHY_RESET == 0 {
            m.mac.insert(at, value);
            m.did_reset();
        } else if !m.spt && at == CTRL && previous & (1 << 16) != 0 && value & (1 << 16) == 0 {
            // Any PCH's LANPHYPC toggle wakes its PHY.
            m.phy_asleep = false;
            m.mac.insert(at, value);
        } else if at == H2ME && value & H2ME_ENFORCE_SETTINGS != 0 && !m.me_stuck {
            // The ME takes the PHY out of ULP and reports it done.
            m.phy_asleep = false;
            let fwsm = m.mac.get(&super::super::FWSM).copied().unwrap_or(0);
            m.mac.insert(super::super::FWSM, fwsm & !ULP_CONFIG_DONE);
            m.mac.insert(at, value);
        } else if m.spt && at == CTRL && previous & (1 << 16) != 0 && value & (1 << 16) == 0 {
            m.power_pending = true;
            m.phy_asleep = false;
            if m.smb_hidden_after_power {
                m.smb_hidden = true;
                let value = m.phy.get(&(1, 769, 23)).copied().unwrap_or(0) | 1;
                m.phy.insert((1, 769, 23), value);
            }
            let ext = m.mac.get(&0x18).copied().unwrap_or(0) & !4;
            m.mac.insert(0x18, ext);
            m.mac.insert(at, value);
        } else if at == PBA {
            m.mac
                .insert(at, (32 - (value & 0xffff)) << 16 | (value & 0xffff));
        } else if at == 0x34 {
            let index = ((value >> 16) & 31) as u8;
            if value & (1 << 21) != 0 {
                let word = m.kmrn.get(&index).copied().unwrap_or(0);
                m.mac.insert(at, (value & !0xffff) | u32::from(word));
            } else {
                m.kmrn.insert(index, value as u16);
                m.mac.insert(at, value);
            }
        } else if at == super::super::MDIC && m.phy_asleep {
            m.mac.insert(at, value & !super::super::MDIC_READY);
        } else if at == super::super::MDIC {
            let index = ((value >> 16) & 31) as u16;
            let address = ((value >> 21) & 31) as u8;
            let smb = m.spt && address == 1 && m.page == 769 && index == 23;
            let mut mdi_error = false;
            let data = if value & super::super::MDIC_WRITE != 0 {
                let switching = smb && m.phy_load(address, index) & 1 != 0 && value & 1 == 0;
                m.phy_store(address, index, value as u16);
                if switching {
                    m.smb_hidden = false;
                    mdi_error = true;
                }
                value as u16
            } else {
                mdi_error =
                    smb && m.smb_hidden && m.mac.get(&0x18).copied().unwrap_or(0) & (1 << 11) == 0;
                m.phy_load(address, index)
            };
            m.mdic_ready_at = m.time + m.mdic_cycle_us;
            let failed =
                (m.mdic_fail_after..m.mdic_fail_after + m.mdic_failures).contains(&m.mdic_attempts);
            m.mdic_attempts += 1;
            let response = (value & !0xffff)
                | u32::from(data)
                | super::super::MDIC_READY
                | if mdi_error { 1 << 30 } else { 0 };
            let response = if failed {
                match m.mdic_kind {
                    0 => response & !(1 << 28),
                    1 => response | (1 << 30),
                    _ => (response & !(31 << 16)) | (7 << 16),
                }
            } else {
                response
            };
            m.mac.insert(at, response);
        } else {
            m.mac.insert(at, value);
        }
        if m.spt && m.config[&0xe4] & 0x100 != 0 {
            if at == 0x3818 && value != previous && m.flush_after_tx {
                let address = u64::from(m.mac[&0x3800]) | (u64::from(m.mac[&0x3804]) << 32);
                assert_ne!(address, 0);
                assert_eq!(
                    m.mac[&0x3808],
                    (crate::ring::DESCRIPTORS * crate::ring::DESCRIPTOR) as u32
                );
                let descriptor = (address as usize + previous as usize * 16) as *const u8;
                // SAFETY: the queue model's published ring belongs
                // to its live synchronous Memory owner, aligned and512B.
                let buffer = unsafe { core::ptr::read_volatile(descriptor.cast::<u64>()) };
                // SAFETY: same descriptor's aligned lower dword.
                let lower = unsafe { core::ptr::read_volatile(descriptor.add(8).cast::<u32>()) };
                assert_eq!(buffer, address);
                assert_eq!(lower, 512 | (1 << 25));
                m.config.insert(0xe4, 0);
            }
            if at == RCTL && value & 2 != 0 && m.flush_after_rx {
                let thresholds = m.mac.get(&0x2828).copied().unwrap_or(0);
                if thresholds & 0x3fff == 0x11f && thresholds & (1 << 24) != 0 {
                    m.config.insert(0xe4, 0);
                }
            }
        }
        Ok(())
    }
}
// SAFETY: config words in the same single Function/reset model as
// the MAC/PHY/flash registers. No separate owner/token supplies values.
unsafe impl super::lpt::LptRegisters for Io {
    fn read_config16(&mut self, at: u16) -> Result<u16, Fault> {
        let mut m = self.0.borrow_mut();
        m.enter()?;
        let value = *m.config.get(&at).expect("actual modeled config word");
        m.operations.push([7, u32::from(at), u32::from(value)]);
        Ok(value)
    }
}
// SAFETY: same single model as its MAC implementation; width-specific
// operations implement the flash register engine, not driver algorithms.
unsafe impl nvm::Registers for Io {
    fn read_mac32(&mut self, at: u32) -> Result<u32, nvm::Error> {
        Registers::read32(self, at).map_err(|_| nvm::Error::Access)
    }
    fn read16(&mut self, at: u32) -> Result<u16, nvm::Error> {
        let mut m = self.0.borrow_mut();
        m.enter().map_err(|_| nvm::Error::Access)?;
        let value = match at {
            4 => 0x4001,
            6 => {
                assert!(!m.spt, "SPT control requires32-bit access");
                m.flash_control
            }
            _ => panic!("invalid flash16"),
        };
        m.operations.push([3, at, u32::from(value)]);
        Ok(value)
    }
    fn read32(&mut self, at: u32) -> Result<u32, nvm::Error> {
        let mut m = self.0.borrow_mut();
        m.enter().map_err(|_| nvm::Error::Access)?;
        let value = match at {
            0 => {
                assert!(!m.spt, "SPT has no GFPREG");
                1 << 16
            }
            4 => {
                assert!(m.spt);
                0x4001 | (u32::from(m.flash_control) << 16)
            }
            16 => {
                let index = m.flash_address as usize / 2;
                if m.spt {
                    u32::from(m.words[index]) | (u32::from(m.words[index + 1]) << 16)
                } else {
                    u32::from(m.words[index]) >> ((m.flash_address & 1) * 8)
                }
            }
            _ => panic!("invalid flash32"),
        };
        m.operations.push([4, at, value]);
        Ok(value)
    }
    fn write16(&mut self, at: u32, value: u16) -> Result<(), nvm::Error> {
        let mut m = self.0.borrow_mut();
        m.enter().map_err(|_| nvm::Error::Access)?;
        m.operations.push([5, at, u32::from(value)]);
        match at {
            4 => {}
            6 => {
                assert_eq!(value & 6, 0, "non-read flash cycle");
                m.flash_control = value & !1;
            }
            _ => panic!("invalid flash16 store"),
        }
        Ok(())
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), nvm::Error> {
        let mut m = self.0.borrow_mut();
        m.enter().map_err(|_| nvm::Error::Access)?;
        m.operations.push([6, at, value]);
        match at {
            4 if m.spt => {
                let control = (value >> 16) as u16;
                assert_eq!(control & 6, 0, "non-read SPT flash cycle");
                m.flash_control = control & !1;
            }
            8 => m.flash_address = value,
            _ => panic!("non-address flash32 store"),
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(super) struct Timer(Rc<RefCell<Model>>, Arc<AtomicUsize>);
impl Timer {
    fn new(state: Rc<RefCell<Model>>) -> Self {
        let drops = state.borrow().timer_drops.clone();
        Self(state, drops)
    }
}
// SAFETY: isolated owned virtual-time model; this grants no native permission.
unsafe impl Delay for Timer {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        if let Some(error) = self.0.borrow().timing_failure {
            Err(error)
        } else {
            Ok(())
        }
    }
    fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
        self.check()?;
        {
            let mut state = self.0.borrow_mut();
            let at = state.delay_calls;
            state.delay_calls += 1;
            if state.fail_delay_at == Some(at) {
                let error = crate::bus::pci::power::Error::Clock;
                state.timing_failure = Some(error);
                return Err(error);
            }
        }
        let mut m = self.0.borrow_mut();
        m.time += us;
        m.operations.push([2, us as u32, 0]);
        Ok(())
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        self.1.fetch_add(1, Ordering::Relaxed);
    }
}

type Fixture = (Rc<RefCell<Model>>, Arc<AtomicUsize>, Io, Timer);
pub(super) fn fixture() -> Fixture {
    let state = Rc::new(RefCell::new(Model::ready()));
    let released = Arc::new(AtomicUsize::new(0));
    (
        state.clone(),
        released.clone(),
        Io(state.clone(), released),
        Timer::new(state.clone()),
    )
}
pub(super) fn start(io: Io, timer: Timer) -> Result<Controller<Io, Timer>, Error> {
    // SAFETY: one fresh exclusive same-function model and real model timer.
    unsafe { Controller::new(0x1503, io, timer) }
}
pub(super) fn fixture_lpt() -> Fixture {
    let (state, released, io, timer) = fixture();
    {
        let mut m = state.borrow_mut();
        m.phy.insert((2, 0, 3), 0xa7);
        m.words[3] |= 1;
        let sum = m.words[..63].iter().copied().fold(0u16, u16::wrapping_add);
        m.words[63] = 0xbabau16.wrapping_sub(sum);
        let strap = m.mac[&STRAP] | (2 << 12);
        m.mac.insert(STRAP, strap);
    }
    (state, released, io, timer)
}
pub(super) fn start_lpt(device: u16, io: Io, timer: Timer) -> Result<Controller<Io, Timer>, Error> {
    // SAFETY: one fresh same-function config/MAC/flash/PHY model epoch.
    unsafe { Controller::new_lpt(device, io, timer) }
}
fn raw(io: Io, timer: Timer) -> Controller<Io, Timer> {
    let bus = Bus(Rc::new(RefCell::new(io)));
    // SAFETY: raw single-function model before any PHY/DMA operation.
    let nvm = unsafe { nvm::Nvm::new(nvm::Layout::Pch2, bus.clone(), timer.clone()) }.unwrap();
    // SAFETY: the same isolated model reset epoch.
    let phy = unsafe { Phy::new(Kind::I82579, bus, timer) };
    Controller {
        phy,
        nvm,
        station: crate::Mac([0; 6]),
        identity: Identity {
            kind: Kind::I82579,
            id: 0,
            revision: 0,
        },
        poisoned: false,
        profile: Profile::I82579,
        config_read: None,
        ulp_exit_failed: false,
    }
}
#[test]
fn cold_composition_uses_real_nvm_and_two_distinct_reset_lifecycles() {
    let (state, released, io, timer) = fixture();
    let controller = start(io, timer).unwrap();
    assert_eq!(controller.station().0, [2, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(
        controller.identity(),
        Identity {
            kind: Kind::I82579,
            id: 0x01540090,
            revision: 3
        }
    );
    assert!(!controller.is_poisoned());
    let m = state.borrow();
    assert_eq!(m.phy[&(1, 769, 20)], 0x125a);
    assert_eq!(m.phy[&(1, 772, 21)], 0x5601);
    assert_eq!(m.phy[&(1, 0, 26)] & 0x3ff, 0x2d5);
    assert_eq!(m.phy[&(1, 0, 30)], 0xa5c7);
    assert_eq!(m.phy[&(1, 0, 25)] & 0x444, OEM_LPLU | OEM_RESTART);
    assert_eq!(m.emi[&MSE_THRESHOLD], 0x34);
    assert_eq!(m.emi[&MSE_LINK_DOWN], 5);
    assert_eq!(m.emi[&LPI_UPDATE_TIMER], 0x1387);
    assert_eq!(m.mac[&RCTL], 0);
    assert_eq!(m.mac[&TCTL], PAD_SHORT);
    assert_eq!(
        m.mac[&super::super::EXTCNF_CTRL] & (GATE_PHY | super::super::SWFLAG),
        0
    );
    let at = m
        .operations
        .iter()
        .position(|o| o[0] == 1 && o[1] == CTRL && o[2] & RESET != 0)
        .unwrap();
    assert_eq!(m.operations[at + 1], [2, 20_000, 0]);
    drop(m);
    drop(controller);
    assert_eq!(released.load(Ordering::SeqCst), 1);
}
#[test]
fn unmanaged_exact_cohort_and_readiness_are_required() {
    for failure in 2..6 {
        let (state, released, io, timer) = fixture();
        {
            let mut m = state.borrow_mut();
            match failure {
                2 => m.init_missing = true,
                3 => m.reset_missing = true,
                4 => m.reset_stuck = true,
                5 => {
                    m.master_busy = 2000;
                }
                _ => unreachable!(),
            }
        }
        let error = match start(io, timer) {
            Ok(_) => panic!("accepted unready model"),
            Err(e) => e,
        };
        assert!(matches!(
            error,
            Error::InitTimeout | Error::ResetNotObserved | Error::ResetStuck | Error::MasterTimeout
        ));
        assert_eq!(
            released.load(Ordering::SeqCst),
            0,
            "uncertain real owner released"
        );
        assert!(
            state
                .borrow()
                .operations
                .iter()
                .all(|o| !(o[0] == 1 && matches!(o[1], RCTL | TCTL) && o[2] & 2 != 0))
        );
    }
    let (_, released, io, timer) = fixture();
    assert!(matches!(
        // SAFETY: test exact-cohort refusal with a fresh model.
        unsafe { Controller::new(0x153a, io, timer) },
        Err(Error::UnsupportedDevice(0x153a))
    ));
    assert_eq!(released.load(Ordering::SeqCst), 1);
}
#[test]
fn each_access_failure_keeps_the_single_function_without_packet_dma() {
    let (state, _, io, timer) = fixture();
    let ready = start(io, timer).unwrap();
    let count = state.borrow().accesses;
    drop(ready);
    for at in 0..count {
        let (state, released, io, timer) = fixture();
        state.borrow_mut().fail_at = Some(at);
        assert!(start(io, timer).is_err(), "lost access failure at {at}");
        assert_eq!(
            released.load(Ordering::SeqCst),
            0,
            "released owner after failure {at}"
        );
        let m = state.borrow();
        assert!(
            m.operations
                .iter()
                .all(|o| !(o[0] == 1 && matches!(o[1], RCTL | TCTL) && o[2] & 2 != 0))
        );
    }
}
#[test]
fn malformed_lcd_never_writes_its_script_or_reports_initialized() {
    for out_of_bounds in [false, true] {
        let (state, released, io, timer) = fixture();
        if out_of_bounds {
            state
                .borrow_mut()
                .mac
                .insert(super::super::EXTCNF_CTRL, 0xfff << 16);
        } else {
            state.borrow_mut().words[128] |= 1;
        }
        assert!(matches!(start(io, timer), Err(Error::Configuration)));
        let m = state.borrow();
        assert!(!m.phy.contains_key(&(1, 769, 20)));
        assert!(!m.phy.contains_key(&(1, 772, 21)));
        assert_eq!(released.load(Ordering::SeqCst), 0);
    }
}
#[test]
#[ignore = "oracle: STELA_E1000E_PCH_RESET_ORACLE"]
fn unchanged_linux_global_reset_prefix_register_effects() {
    let path = std::env::var_os("STELA_E1000E_PCH_RESET_ORACLE").expect("reset trace path");
    let bytes = std::fs::read(path).expect("read reset trace");
    assert_eq!(bytes.len() % 4, 0);
    let words: Vec<_> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| u32::from_le_bytes(*b))
        .collect();
    let mut cursor = 0;
    let mut cases = 0;
    while cursor < words.len() {
        let busy = words[cursor];
        let count = words[cursor + 1] as usize;
        cursor += 2;
        let expected: Vec<[u32; 3]> = words[cursor..cursor + count * 3]
            .as_chunks::<3>()
            .0
            .to_vec();
        cursor += count * 3;
        let (state, _, io, timer) = fixture();
        let mut controller = raw(io, timer);
        state.borrow_mut().operations.clear();
        state.borrow_mut().master_busy = busy as usize;
        controller.global_reset().unwrap();
        // The source oracle's declared reset prefix compares all
        // stores, STATUS observations and delays. Extra Stela read-only
        // validation/CTRL-reset-clear checks are covered separately.
        let actual: Vec<_> = state
            .borrow()
            .operations
            .iter()
            .copied()
            .filter(|o| o[0] == 1 || o[0] == 2 || (o[0] == 0 && o[1] == STATUS))
            .collect();
        assert_eq!(actual, expected, "master-busy polls={busy}");
        cases += 1;
    }
    assert_eq!(cases, 3);
}
pub(super) fn post_effects(operations: &[[u32; 3]], initial_ext: u32) -> Vec<[u32; 3]> {
    let mut actual = Vec::new();
    let mut page = 0;
    let mut pending = None;
    let mut ext = initial_ext;
    for &[kind, at, value] in operations {
        if kind == 2 && at >= 10_000 {
            actual.push([2, at, 0]);
        }
        if kind == 1 && at == super::super::EXTCNF_CTRL {
            if (ext ^ value) & GATE_PHY != 0 {
                actual.push([1, at, value & !super::super::SWFLAG]);
            }
            ext = value;
        }
        if at != super::super::MDIC {
            continue;
        }
        if kind == 1 {
            let index = (value >> 16) & 31;
            if index == 31 {
                page = (value & 0xffff) >> 5;
                continue;
            }
            let address = (value >> 21) & 31;
            let logical = if index <= 15 {
                index
            } else {
                ((if address == 1 && page == 0 { 768 } else { page }) << 5) | index
            };
            if value & super::super::MDIC_WRITE != 0 {
                actual.push([11, logical, value & 0xffff]);
            } else {
                pending = Some(logical);
            }
        } else if kind == 0
            && let Some(logical) = pending.take()
        {
            actual.push([10, logical, value & 0xffff]);
        }
    }
    actual
}
#[test]
#[ignore = "oracle: STELA_E1000E_PCH_POST_ORACLE"]
fn unchanged_linux_post_reset_lcd_and_oem_effects() {
    let path = std::env::var_os("STELA_E1000E_PCH_POST_ORACLE").expect("post-reset trace path");
    let bytes = std::fs::read(path).expect("read post-reset trace");
    assert_eq!(bytes.len() % 4, 0);
    let words: Vec<_> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| u32::from_le_bytes(*b))
        .collect();
    let mut cursor = 0;
    let mut cases = 0;
    while cursor < words.len() {
        let [sw, count, oem, strap, operations] =
            *words[cursor..cursor + 5].first_chunk::<5>().unwrap();
        cursor += 5;
        let expected = words[cursor..cursor + operations as usize * 3]
            .as_chunks::<3>()
            .0
            .to_vec();
        cursor += operations as usize * 3;
        let (state, _, io, timer) = fixture();
        let mut controller = raw(io, timer);
        let initial_ext = (64 << 16) | GATE_PHY;
        {
            let mut m = state.borrow_mut();
            m.operations.clear();
            m.mac.insert(super::super::EXTCNF_CTRL, initial_ext);
            m.mac.insert(FEXTNVM, if sw == 0 { 0 } else { SW_CONFIG });
            m.mac.insert(EXTCNF_SIZE, count << 16);
            m.mac.insert(
                PHY_CTRL,
                if oem & 1 == 0 { 0 } else { 2 } | if oem & 2 == 0 { 0 } else { 0x40 },
            );
            m.mac.insert(STRAP, if strap == 0 { 0 } else { 0x55 << 17 });
            m.mac
                .insert(LEDCTL, if strap == 0 { 0x5a38 } else { 0xa5c7 });
            m.phy.clear();
            for (address, page, index, data) in [
                (1, 769, 16, 0x5252),
                (1, 769, 17, 0x77f7),
                (1, 0, 26, 0xa511),
                (1, 0, 30, 0x9632),
                (1, 0, 25, 0xa09c),
            ] {
                m.phy.insert((address, page, index), data);
            }
        }
        controller.post_reset().unwrap();
        let actual = post_effects(&state.borrow().operations, initial_ext);
        assert_eq!(
            actual, expected,
            "sw={sw} count={count} oem={oem} strap={strap}"
        );
        cases += 1;
    }
    assert_eq!(cases, 32);
}

#[test]
fn missing_minimum_before_each_cold_profile_keeps_original_io_and_provider() {
    for device in [0x1502, 0x153a, 0x156f] {
        let (state, released, io, timer) = fixture();
        let cause = crate::bus::pci::power::Error::Clock;
        state.borrow_mut().timing_failure = Some(cause);
        // SAFETY: same isolated model pair; no native hardware permission.
        let result = unsafe {
            match device {
                0x1502 => Controller::new(device, io, timer),
                0x153a => Controller::new_lpt(device, io, timer),
                _ => Controller::new_spt(device, io, timer),
            }
        };
        match result {
            Err(error) => assert_eq!(error, Fault::Minimum(cause).into()),
            Ok(_) => panic!("unavailable minimum admitted"),
        }
        assert!(state.borrow().operations.is_empty());
        assert_eq!(released.load(Ordering::SeqCst), 0);
        assert_eq!(state.borrow().timer_drops.load(Ordering::SeqCst), 0);
    }
}

fn phy_resets(state: &Rc<RefCell<Model>>) -> usize {
    state
        .borrow()
        .operations
        .iter()
        .filter(|o| o[0] == 1 && o[1] == CTRL && o[2] & PHY_RESET != 0)
        .count()
}

fn lanphypc_toggles(state: &Rc<RefCell<Model>>) -> usize {
    state
        .borrow()
        .operations
        .iter()
        .filter(|o| o[0] == 1 && o[1] == CTRL && o[2] & LANPHYPC_OVERRIDE != 0)
        .count()
}

/// `e1000_init_phy_workarounds_pchlan`: an 82579 whose PHY the last owner
/// left behind SMBus is woken by the LANPHYPC toggle, not refused.
#[test]
fn an_82579_phy_left_in_smbus_mode_is_woken_by_the_lanphypc_toggle() {
    let (state, released, io, timer) = fixture();
    state.borrow_mut().phy_asleep = true;
    let controller = start(io, timer).unwrap();
    assert_eq!(lanphypc_toggles(&state), 1);
    assert!(!controller.is_poisoned());
    drop(controller);
    assert_eq!(released.load(Ordering::SeqCst), 1);
}

/// An adapter the Intel ME manages starts: the PHY is shared through the
/// software flag, the PHY configuration stays gated as Linux leaves a
/// managed 82579, and no LANPHYPC toggle runs on an answering PHY.
#[test]
fn an_82579_the_me_manages_starts_with_its_phy_configuration_gated() {
    let (state, _, io, timer) = fixture();
    state.borrow_mut().mac.insert(
        super::super::FWSM,
        super::super::FW_VALID | super::super::RESET_PERMITTED,
    );
    let controller = start(io, timer).unwrap();
    assert_eq!(lanphypc_toggles(&state), 0);
    assert!(phy_resets(&state) >= 2);
    assert_ne!(
        state.borrow().mac[&super::super::EXTCNF_CTRL] & GATE_PHY,
        0,
        "Linux keeps a managed 82579's automatic PHY configuration gated"
    );
    drop(controller);
}

/// A PHY reset the ME blocks is left out, as `e1000e_phy_hw_reset_generic`
/// leaves it out, and the adapter still starts; a PHY that does not answer
/// while the ME blocks its wake-up is refused with that reason.
#[test]
fn a_phy_reset_the_me_blocks_is_left_out_and_a_blocked_wake_is_named() {
    let (state, _, io, timer) = fixture();
    state.borrow_mut().mac.insert(super::super::FWSM, 0);
    let controller = start(io, timer).unwrap();
    assert_eq!(phy_resets(&state), 0);
    drop(controller);

    let (state, released, io, timer) = fixture();
    {
        let mut m = state.borrow_mut();
        m.mac.insert(super::super::FWSM, 0);
        m.phy_asleep = true;
    }
    assert!(matches!(start(io, timer), Err(Error::RecoveryBlocked)));
    assert_eq!(lanphypc_toggles(&state), 0);
    assert_eq!(released.load(Ordering::SeqCst), 0);
}

/// `e1000_phy_is_accessible_pchlan` takes any valid PHY ID as an answer:
/// a PHY that answers with another ID is named as the wrong PHY by the
/// identity check after recovery, with no LANPHYPC toggle before it.
#[test]
fn a_wrong_phy_that_answers_is_named_without_a_lanphypc_toggle() {
    let (state, released, io, timer) = fixture_lpt();
    state.borrow_mut().phy.insert((2, 0, 3), 0x00b7);
    assert!(matches!(
        start_lpt(0x153a, io, timer),
        Err(Error::Phy(error)) if error.primary == Fault::WrongPhy(0x0154_00b7)
    ));
    assert_eq!(lanphypc_toggles(&state), 0);
    assert_eq!(released.load(Ordering::SeqCst), 0);
}

/// An LPT PHY left behind SMBus is found with the MAC forced to SMBus mode
/// or woken by the toggle, and the MAC ends out of SMBus mode.
#[test]
fn an_lpt_phy_left_in_smbus_mode_is_woken_and_the_mac_leaves_smbus_mode() {
    let (state, _, io, timer) = fixture_lpt();
    state.borrow_mut().phy_asleep = true;
    let controller = start_lpt(0x153a, io, timer).unwrap();
    assert_eq!(lanphypc_toggles(&state), 1);
    assert_eq!(
        state.borrow().mac.get(&CTRL_EXT).copied().unwrap_or(0) & FORCE_SMBUS,
        0
    );
    drop(controller);
}
