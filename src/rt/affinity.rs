pub fn pin_core(queue: u32) {
    let core_ids = core_affinity::get_core_ids().unwrap();
    let index = queue as usize % core_ids.len();
    let core_id = core_ids[index];

    core_affinity::set_for_current(core_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_core_queue_zero() {
        // Should not panic — queue 0 always exists.
        pin_core(0);
    }

    #[test]
    fn pin_core_wraps_on_overflow() {
        // Should not panic even if queue_id exceeds core count.
        let num_cores = core_affinity::get_core_ids().unwrap().len() as u32;
        pin_core(num_cores + 1);
    }
}
