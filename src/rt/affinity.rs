pub fn pin_last_core() {
    let core_ids = core_affinity::get_core_ids().unwrap();
    let core_id = *core_ids.last().unwrap();

    core_affinity::set_for_current(core_id);
}

pub fn pin_second_last_core() {
    let core_ids = core_affinity::get_core_ids().unwrap();
    let core_id = *core_ids.get(core_ids.len() - 2).unwrap();

    core_affinity::set_for_current(core_id);
}

pub fn pin_first_core() {
    let core_ids = core_affinity::get_core_ids().unwrap();
    let core_id = *core_ids.first().unwrap();

    core_affinity::set_for_current(core_id);
}
