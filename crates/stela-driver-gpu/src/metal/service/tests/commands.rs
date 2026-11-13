use super::{
    Memory, Stream, TestService, call, commit, connect, new_buffer, new_function, new_library,
    render_pipeline_request, service, status, submitted, texture,
};
use crate::metal::{
    abi::{
        CompareFunction, CullMode, DispatchType, LoadAction, PrimitiveType, SamplerAddressMode,
        SamplerBorderColor, SamplerMinMagFilter, SamplerMipFilter, SamplerReductionMode,
        StencilOperation, StorageMode, StoreAction, TextureUsage,
    },
    service::wire::{
        self, ComputePipelineResponse, CounterSetCode, Empty, Handle, NewComputePipelineRequest,
        NewCounterBufferRequest, Operation, RenderPipelineResponse, SamplerDescriptorRecord,
        SamplerResponse, Status, TextureDescriptorRecord, TextureResponse, Value,
        commands::{
            BeginCompute, BeginRender, BlitCode, ColorStoreActionOptions, CommandBufferCode,
            ComputeCode, CopyBuffer, DepthStencilRecord, Dispatch, DrawPrimitives, FillBuffer,
            MappingRecord, Mode, PassAttachmentRecord, RenderCode, ResolveCounters, Resource,
            ResourceStateCode, SampleCounters, SetBuffer, SetBytes, SetPipeline, StageSampler,
            StencilRecord, UpdateMappings, ViewportRecord,
        },
    },
    vulkan::{PipelineBindPoint, command::Command},
};

#[test]
fn compute_commands_replay_into_a_submitted_command_buffer() {
    let mut service = service();
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let library = new_library(&mut service, connection, memory);
    let kernel = new_function(&mut service, connection, library, "kernel", &[], memory)
        .unwrap()
        .handle;
    let request = NewComputePipelineRequest {
        compute_function: kernel,
        ..Default::default()
    };
    let pipeline: ComputePipelineResponse = call(
        &mut service,
        connection,
        Operation::NewComputePipeline,
        &request,
        memory,
    )
    .unwrap();
    let buffer = new_buffer(&mut service, connection, StorageMode::Shared);
    let mut stream = Stream::default();
    let begin = BeginCompute {
        dispatch_type: DispatchType::Serial.raw(),
    };
    let dispatch = Dispatch {
        size: [4, 1, 1],
        threads: [32, 1, 1],
    };
    stream
        .push(ComputeCode::Begin.raw(), &begin, &[])
        .push(
            ComputeCode::SetPipeline.raw(),
            &SetPipeline {
                pipeline: pipeline.handle,
            },
            &[],
        )
        .push(
            ComputeCode::SetBuffer.raw(),
            &SetBuffer {
                buffer,
                offset: 0,
                index: 0,
            },
            &[],
        )
        .push(
            ComputeCode::SetBytes.raw(),
            &SetBytes { index: 1 },
            &[7; 12],
        )
        .push(ComputeCode::DispatchThreadgroups.raw(), &dispatch, &[])
        .end();
    assert_eq!(
        commit(&mut service, connection, &stream),
        Ok(Value { value: 1 })
    );
    assert!(submitted(&mut service).contains(&Command::Dispatch([4, 1, 1])));
}

#[test]
fn blit_commands_copy_fill_and_synchronize() {
    let mut service = service();
    let connection = connect(&mut service);
    let managed = new_buffer(&mut service, connection, StorageMode::Managed);
    let shared = new_buffer(&mut service, connection, StorageMode::Shared);
    let blit = |stream: &mut Stream| {
        stream.push(BlitCode::Begin.raw(), &Empty {}, &[]);
    };
    let fill = FillBuffer {
        buffer: managed,
        start: 0,
        length: 256,
        value: 7,
    };
    let copy = CopyBuffer {
        source: managed,
        source_offset: 0,
        destination: shared,
        destination_offset: 0,
        size: 256,
    };
    let mut stream = Stream::default();
    blit(&mut stream);
    stream
        .push(BlitCode::FillBuffer.raw(), &fill, &[])
        .push(BlitCode::CopyBuffer.raw(), &copy, &[])
        .push(
            BlitCode::Synchronize.raw(),
            &Resource { resource: managed },
            &[],
        )
        .end();
    assert_eq!(
        commit(&mut service, connection, &stream),
        Ok(Value { value: 1 })
    );
    let commands = submitted(&mut service);
    assert!(commands.iter().any(|command| matches!(
        command,
        Command::FillBuffer {
            data: 0x0707_0707,
            ..
        }
    )));
    assert!(
        commands
            .iter()
            .any(|command| matches!(command, Command::CopyBuffer { .. }))
    );

    // Only managed resources synchronize, and fills take one byte.
    let mut stream = Stream::default();
    blit(&mut stream);
    stream.push(
        BlitCode::Synchronize.raw(),
        &Resource { resource: shared },
        &[],
    );
    assert_eq!(
        commit(&mut service, connection, &stream).map_err(|outcome| outcome.reason),
        Err("synchronizeResource: is for managed resources")
    );
    let mut stream = Stream::default();
    blit(&mut stream);
    let wide = FillBuffer { value: 256, ..fill };
    stream.push(BlitCode::FillBuffer.raw(), &wide, &[]);
    assert_eq!(
        status(commit(&mut service, connection, &stream)),
        Status::Malformed
    );
}

#[test]
fn refused_commands_discard_the_command_buffer() {
    let mut service = service();
    let connection = connect(&mut service);
    let buffer = new_buffer(&mut service, connection, StorageMode::Shared);
    let refused = |stream: Stream| status(commit(&mut service, connection, &stream));
    let mut unknown = Stream::default();
    unknown.push(0x7f01, &Empty {}, &[]);
    let mut truncated = Stream::default();
    truncated.push(BlitCode::Begin.raw(), &Empty {}, &[]);
    truncated.0.truncate(4);
    let mut short = Stream::default();
    short.push(BlitCode::Begin.raw(), &Empty {}, &[0; 8]);
    let mut unencoded = Stream::default();
    let dispatch = Dispatch {
        size: [1; 3],
        threads: [1; 3],
    };
    unencoded.push(ComputeCode::DispatchThreadgroups.raw(), &dispatch, &[]);
    let mut stale = Stream::default();
    let synchronize = Resource {
        resource: buffer + 1,
    };
    stale.push(BlitCode::Begin.raw(), &Empty {}, &[]).push(
        BlitCode::Synchronize.raw(),
        &synchronize,
        &[],
    );
    let mut open = Stream::default();
    open.push(BlitCode::Begin.raw(), &Empty {}, &[]);
    assert_eq!(
        [unknown, truncated, short, unencoded, stale, open].map(refused),
        [
            Status::UnknownOperation,
            Status::Malformed,
            Status::Malformed,
            Status::Invalid,
            Status::StaleHandle,
            Status::Invalid,
        ]
    );
    assert_eq!(
        commit(&mut service, connection, &Stream::default()),
        Ok(Value { value: 1 }),
        "nothing refused was submitted"
    );
}

#[test]
fn render_passes_replay_their_state_and_draws() {
    let mut service = service();
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let library = new_library(&mut service, connection, memory);
    let mut function = |name| {
        new_function(&mut service, connection, library, name, &[], memory)
            .unwrap()
            .handle
    };
    let (vertex, fragment) = (function("vertex"), function("fragment"));
    let pipeline: RenderPipelineResponse = call(
        &mut service,
        connection,
        Operation::NewRenderPipeline,
        &render_pipeline_request(vertex, fragment),
        memory,
    )
    .unwrap();
    let target = TextureDescriptorRecord {
        usage: TextureUsage::RENDER_TARGET.bits(),
        ..texture(StorageMode::Private)
    };
    let target: TextureResponse = call(
        &mut service,
        connection,
        Operation::NewTexture,
        &target,
        memory,
    )
    .unwrap();

    let mut begin = BeginRender::default();
    begin.color_attachments[0].attachment = PassAttachmentRecord {
        texture: target.handle,
        load_action: LoadAction::Clear.raw(),
        store_action: StoreAction::Store.raw(),
        ..Default::default()
    };
    let viewport = ViewportRecord {
        width: 8.0,
        height: 4.0,
        zfar: 1.0,
        ..Default::default()
    };
    let stencil = StencilRecord {
        compare_function: CompareFunction::Always.raw(),
        stencil_failure_operation: StencilOperation::Keep.raw(),
        depth_failure_operation: StencilOperation::Keep.raw(),
        depth_stencil_pass_operation: StencilOperation::Keep.raw(),
        read_mask: u32::MAX,
        write_mask: u32::MAX,
    };
    let depth_stencil = DepthStencilRecord {
        depth_compare_function: CompareFunction::Less.raw(),
        depth_write_enabled: 1,
        reserved: 0,
        front_face_stencil: stencil,
        back_face_stencil: stencil,
    };
    let draw = DrawPrimitives {
        primitive: PrimitiveType::Triangle.raw(),
        vertex_start: 0,
        vertex_count: 3,
        instance_count: 1,
        base_instance: 0,
    };
    let mut stream = Stream::default();
    stream
        .push(RenderCode::Begin.raw(), &begin, &[])
        .push(
            RenderCode::SetPipeline.raw(),
            &SetPipeline {
                pipeline: pipeline.handle,
            },
            &[],
        )
        .push(
            RenderCode::SetViewports.raw(),
            &Empty {},
            wire::bytes(&viewport),
        )
        .push(
            RenderCode::SetCullMode.raw(),
            &Mode {
                mode: CullMode::Back.raw(),
            },
            &[],
        )
        .push(RenderCode::SetDepthStencilState.raw(), &depth_stencil, &[])
        .push(RenderCode::DrawPrimitives.raw(), &draw, &[])
        .push(
            RenderCode::SetColorStoreActionOptions.raw(),
            &ColorStoreActionOptions {
                options: 0,
                index: 0,
            },
            &[],
        )
        .end();
    assert_eq!(
        commit(&mut service, connection, &stream),
        Ok(Value { value: 1 })
    );
    let commands = submitted(&mut service);
    assert!(
        commands
            .iter()
            .any(|command| matches!(command, Command::BeginRendering(_)))
    );
    assert!(commands.iter().any(|command| matches!(
        command,
        Command::Draw {
            vertex_count: 3,
            instance_count: 1,
            ..
        }
    )));

    // A pass declaring more counter samples than its data holds.
    let mut stream = Stream::default();
    let short = BeginRender {
        counter_sample_count: 1,
        ..begin
    };
    stream.push(RenderCode::Begin.raw(), &short, &[]);
    assert_eq!(
        status(commit(&mut service, connection, &stream)),
        Status::Malformed
    );

    // Options Metal does not define.
    let mut stream = Stream::default();
    stream.push(RenderCode::Begin.raw(), &begin, &[]).push(
        RenderCode::SetDepthStoreActionOptions.raw(),
        &Mode { mode: 1 << 8 },
        &[],
    );
    assert_eq!(
        status(commit(&mut service, connection, &stream)),
        Status::Malformed
    );
}

/// A pass the device refuses leaves a note naming why with its
/// attachments; one whose image memory a job makes defers, answered
/// `Pending`, and is no refusal: it leaves no note.
#[test]
fn refused_passes_note_why_and_deferred_ones_note_nothing() {
    use crate::metal::{service::wire::NewBufferTextureRequest, vulkan::backend::Backend};
    let mut service = service();
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let usage = (TextureUsage::RENDER_TARGET | TextureUsage::SHADER_READ).bits();
    let buffer = super::cpu_buffer(&mut service, connection, 4096, StorageMode::Shared);
    // An IOSurface's texture, over a buffer's rows.
    let surface: TextureResponse = call(
        &mut service,
        connection,
        Operation::NewBufferTexture,
        &NewBufferTextureRequest {
            buffer: buffer.handle,
            descriptor: TextureDescriptorRecord {
                usage,
                ..texture(StorageMode::Shared)
            },
            offset: 0,
            bytes_per_row: 256,
            second_offset: 0,
            second_bytes_per_row: 0,
            surface_format: 0,
        },
        memory,
    )
    .unwrap();
    let memoryless: TextureResponse = call(
        &mut service,
        connection,
        Operation::NewTexture,
        &TextureDescriptorRecord {
            usage,
            ..texture(StorageMode::Memoryless)
        },
        memory,
    )
    .unwrap();
    let pass = |scratch_load: LoadAction| {
        let mut begin = BeginRender::default();
        begin.color_attachments[0].attachment = PassAttachmentRecord {
            texture: surface.handle,
            load_action: LoadAction::Load.raw(),
            store_action: StoreAction::Store.raw(),
            ..Default::default()
        };
        begin.color_attachments[1].attachment = PassAttachmentRecord {
            texture: memoryless.handle,
            load_action: scratch_load.raw(),
            store_action: StoreAction::DontCare.raw(),
            ..Default::default()
        };
        let mut stream = Stream::default();
        stream.push(RenderCode::Begin.raw(), &begin, &[]).end();
        stream
    };

    // Its first run makes the surface's storage copy, whose memory a job
    // makes.
    let lock = crate::metal::deferred::JobLock {
        lock: alloc::sync::Arc::new(crate::metal::compiler::CompileLock::new()),
        relax: || {},
    };
    let backend = service.device().backend();
    backend.defer_pipelines(Some(&lock));
    backend.image_gate = Some(alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(
        true,
    )));
    let stream = pass(LoadAction::DontCare);
    assert!(commit(&mut service, connection, &stream).is_err());
    assert_eq!(service.noted, None);
    let backend = service.device().backend();
    backend.stop_deferring();
    assert!(backend.take_job().is_some());
    assert!(commit(&mut service, connection, &stream).is_ok());
    assert_eq!(service.noted, None);

    // Metal never loads a memoryless attachment.
    let stream = pass(LoadAction::Load);
    assert_eq!(
        status(commit(&mut service, connection, &stream)),
        Status::Invalid
    );
    let noted = service.noted.take().unwrap();
    assert!(
        noted.starts_with("PASS REFUSED (") && noted.contains("never loaded"),
        "{noted}"
    );
    assert!(
        noted.contains("color1=[Rgba8Unorm 8x4x1 samples=1 storage=Memoryless"),
        "{noted}"
    );
}

/// A render pass that draws through a linear sampler, then through a
/// bicubic one, which needs a variant of its pipeline.
fn bicubic_draws(service: &mut TestService, connection: core::num::NonZeroU64) -> Stream {
    let memory = &mut Memory::default();
    let library = new_library(service, connection, memory);
    let mut function = |name| {
        new_function(service, connection, library, name, &[], memory)
            .unwrap()
            .handle
    };
    let (vertex, fragment) = (function("vertex"), function("filtering"));
    let pipeline: RenderPipelineResponse = call(
        service,
        connection,
        Operation::NewRenderPipeline,
        &render_pipeline_request(vertex, fragment),
        memory,
    )
    .unwrap();
    let target = TextureDescriptorRecord {
        usage: TextureUsage::RENDER_TARGET.bits(),
        ..texture(StorageMode::Private)
    };
    let target: TextureResponse =
        call(service, connection, Operation::NewTexture, &target, memory).unwrap();
    let mut sampler = |filter: SamplerMinMagFilter| {
        let descriptor = SamplerDescriptorRecord {
            min_filter: filter.raw(),
            mag_filter: filter.raw(),
            mip_filter: SamplerMipFilter::NotMipmapped.raw(),
            max_anisotropy: 1,
            address_modes: [SamplerAddressMode::ClampToEdge.raw(); 3],
            border_color: SamplerBorderColor::TransparentBlack.raw(),
            reduction_mode: SamplerReductionMode::WeightedAverage.raw(),
            compare_function: CompareFunction::Never.raw(),
            lod_min_clamp: 0.0,
            lod_max_clamp: f32::MAX,
            normalized_coordinates: 1,
            reserved: 0,
        };
        let sampler: SamplerResponse = call(
            service,
            connection,
            Operation::NewSampler,
            &descriptor,
            memory,
        )
        .unwrap();
        sampler.handle
    };
    let (linear, bicubic) = (
        sampler(SamplerMinMagFilter::Linear),
        sampler(SamplerMinMagFilter::Bicubic),
    );

    let mut begin = BeginRender::default();
    begin.color_attachments[0].attachment = PassAttachmentRecord {
        texture: target.handle,
        load_action: LoadAction::Clear.raw(),
        store_action: StoreAction::Store.raw(),
        ..Default::default()
    };
    let draw = DrawPrimitives {
        primitive: PrimitiveType::Triangle.raw(),
        vertex_start: 0,
        vertex_count: 3,
        instance_count: 1,
        base_instance: 0,
    };
    let set_sampler = |sampler| StageSampler {
        stage: 2,
        sampler,
        index: 1,
        clamped: 0,
        lod_min: 0.0,
        lod_max: 0.0,
        reserved: 0,
    };
    let mut stream = Stream::default();
    stream
        .push(RenderCode::Begin.raw(), &begin, &[])
        .push(
            RenderCode::SetPipeline.raw(),
            &SetPipeline {
                pipeline: pipeline.handle,
            },
            &[],
        )
        .push(RenderCode::SetSampler.raw(), &set_sampler(linear), &[])
        .push(RenderCode::DrawPrimitives.raw(), &draw, &[])
        .push(RenderCode::SetSampler.raw(), &set_sampler(bicubic), &[])
        .push(RenderCode::DrawPrimitives.raw(), &draw, &[])
        .end();
    stream
}

#[test]
fn draws_through_bicubic_samplers_run_a_cached_variant() {
    let mut service = service();
    let connection = connect(&mut service);
    let stream = bicubic_draws(&mut service, connection);
    let compiled = service.device().compiler_mut().compiled.len();
    let bound = |service: &mut TestService| -> alloc::vec::Vec<_> {
        submitted(service)
            .into_iter()
            .filter_map(|command| match command {
                Command::BindPipeline {
                    bind_point: PipelineBindPoint::Graphics,
                    pipeline,
                } => Some(pipeline),
                _ => None,
            })
            .collect()
    };
    for _ in 0..2 {
        assert!(commit(&mut service, connection, &stream).is_ok());
        let bound = bound(&mut service);
        // The linear and bicubic draws run different variants.
        assert_eq!(bound.len(), 2);
        assert_ne!(bound[0], bound[1]);
    }
    // The variants compiled for the first commit: the pipeline was made
    // before the connection's first bicubic sampler, so the linear draw
    // runs one too, and the bicubic draw's fragment function filters the
    // sampler at index 1 bicubically.
    let variant: alloc::vec::Vec<_> = service.device().compiler_mut().compiled[compiled..]
        .iter()
        .map(|specialization| specialization.bicubic_samplers)
        .collect();
    assert_eq!(variant, [0, 0, 0, 1 << 1]);
}

#[test]
fn a_deferred_commit_signals_its_events_only_when_it_runs_again() {
    use crate::metal::service::wire::commands::EventCommand;
    let mut service = service();
    let connection = connect(&mut service);
    let event: Handle = call(
        &mut service,
        connection,
        Operation::NewEvent,
        &Empty {},
        &mut Memory::default(),
    )
    .unwrap();
    let mut stream = bicubic_draws(&mut service, connection);
    let signal = EventCommand {
        event: event.handle,
        value: 7,
    };
    stream.push(CommandBufferCode::SignalEvent.raw(), &signal, &[]);
    let submissions = |service: &mut TestService| service.device().backend().submissions.len();
    let before = submissions(&mut service);
    // The bicubic variant's compilation defers: the commit fails, to run
    // again, and submits nothing, its signal included.
    service.device().compiler_mut().defer_next = true;
    assert!(commit(&mut service, connection, &stream).is_err());
    assert_eq!(submissions(&mut service), before);
    service.device().compiler_mut().deferred = false;
    // Run again, it submits the draws and the signal after them, once.
    assert!(commit(&mut service, connection, &stream).is_ok());
    assert_eq!(submissions(&mut service), before + 1);
    let signals: alloc::vec::Vec<_> = service
        .device()
        .backend()
        .submissions
        .last()
        .unwrap()
        .iter()
        .flat_map(|segment| segment.signals.iter().map(|&(_, value)| value))
        .filter(|&value| value == 7)
        .collect();
    assert_eq!(signals, [7]);
}

#[test]
fn encoders_sample_and_resolve_counters() {
    let mut service = service();
    let connection = connect(&mut service);
    let request = NewCounterBufferRequest {
        counter_set: CounterSetCode::Timestamp.raw(),
        sample_count: 2,
    };
    let counters: Handle = call(
        &mut service,
        connection,
        Operation::NewCounterBuffer,
        &request,
        &mut Memory::default(),
    )
    .unwrap();
    let destination = new_buffer(&mut service, connection, StorageMode::Shared);
    let sample = |index, barrier| SampleCounters {
        buffer: counters.handle,
        index,
        barrier,
        reserved: 0,
    };
    let resolve = ResolveCounters {
        buffer: counters.handle,
        first: 0,
        count: 2,
        destination,
        offset: 0,
    };
    let mut stream = Stream::default();
    stream
        .push(BlitCode::Begin.raw(), &Empty {}, &[])
        .push(CommandBufferCode::SampleCounters.raw(), &sample(0, 1), &[])
        .push(CommandBufferCode::SampleCounters.raw(), &sample(1, 0), &[])
        .push(BlitCode::ResolveCounters.raw(), &resolve, &[])
        .end();
    assert_eq!(
        commit(&mut service, connection, &stream),
        Ok(Value { value: 1 })
    );
    let commands = submitted(&mut service);
    let count = |matches: fn(&Command) -> bool| commands.iter().filter(|c| matches(c)).count();
    assert_eq!(
        count(|command| matches!(command, Command::WriteTimestamp { .. })),
        2 + 2,
        "the samples and the command buffer's GPU times"
    );
    assert_eq!(
        count(|command| matches!(command, Command::CopyQueryResults { count: 2, .. })),
        1
    );

    let mut beyond = Stream::default();
    beyond.push(CommandBufferCode::SampleCounters.raw(), &sample(2, 0), &[]);
    assert_eq!(
        status(commit(&mut service, connection, &beyond)),
        Status::Invalid
    );
}

#[test]
fn mapping_updates_name_sparse_textures() {
    let mut service = service();
    let connection = connect(&mut service);
    let dense: TextureResponse = call(
        &mut service,
        connection,
        Operation::NewTexture,
        &texture(StorageMode::Private),
        &mut Memory::default(),
    )
    .unwrap();
    let region = MappingRecord {
        size: [1; 3],
        ..Default::default()
    };
    let update = UpdateMappings {
        texture: dense.handle,
        mode: 0,
    };
    let mut stream = Stream::default();
    stream
        .push(ResourceStateCode::Begin.raw(), &Empty {}, &[])
        .push(
            ResourceStateCode::UpdateMappings.raw(),
            &update,
            wire::bytes(&region),
        );
    assert_eq!(
        commit(&mut service, connection, &stream).map_err(|outcome| outcome.reason),
        Err("the texture is not sparse")
    );
}
