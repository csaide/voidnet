pub fn pin_core(queue: u32) {
    let core_ids = core_affinity::get_core_ids().unwrap();
    let core_id = *core_ids.get(queue as usize).unwrap();

    core_affinity::set_for_current(core_id);
}
