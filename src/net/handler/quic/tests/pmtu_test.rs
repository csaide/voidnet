use crate::net::handler::quic::path::{PmtuPhase, PmtuState};

const DEFAULT_FLOOR: u16 = 1200;
const DEFAULT_CEILING: u16 = 1452;
const STEP_THRESHOLD: u16 = 20;

#[test]
fn pmtu_initial_state_is_disabled() {
    let state = PmtuState::new(DEFAULT_CEILING);
    assert_eq!(state.phase(), PmtuPhase::Disabled);
    assert_eq!(state.floor(), DEFAULT_FLOOR);
    assert_eq!(state.ceiling(), DEFAULT_CEILING);
    assert_eq!(state.current_mtu(), DEFAULT_FLOOR);
}

#[test]
fn pmtu_start_searching() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    assert_eq!(state.phase(), PmtuPhase::Searching);
    assert_eq!(
        state.next_probe_size(),
        (DEFAULT_FLOOR + DEFAULT_CEILING) / 2
    );
}

#[test]
fn pmtu_probe_ack_raises_floor() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    let probe_size = state.next_probe_size();
    state.set_probe_pn(42);
    let result = state.on_probe_acked(42, STEP_THRESHOLD);
    assert!(result.is_searching());
    assert_eq!(state.floor(), probe_size);
}

#[test]
fn pmtu_probe_loss_lowers_ceiling() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    let probe_size = state.next_probe_size();
    state.set_probe_pn(42);
    state.on_probe_lost(STEP_THRESHOLD);
    state.on_probe_lost(STEP_THRESHOLD);
    let result = state.on_probe_lost(STEP_THRESHOLD);
    assert_eq!(state.ceiling(), probe_size);
}

#[test]
fn pmtu_converges_to_search_complete() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    for _ in 0..10 {
        let pn = 100;
        state.set_probe_pn(pn);
        let result = state.on_probe_acked(pn, STEP_THRESHOLD);
        if result.is_complete() {
            break;
        }
    }
    assert_eq!(state.phase(), PmtuPhase::SearchComplete);
    assert!(state.ceiling() - state.floor() < STEP_THRESHOLD);
}

#[test]
fn pmtu_reset_on_migration() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    state.set_probe_pn(1);
    state.on_probe_acked(1, STEP_THRESHOLD);
    state.reset(DEFAULT_CEILING);
    assert_eq!(state.phase(), PmtuPhase::Disabled);
    assert_eq!(state.floor(), DEFAULT_FLOOR);
    assert_eq!(state.current_mtu(), DEFAULT_FLOOR);
}

#[test]
fn pmtu_icmp_reduces_floor() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    state.set_probe_pn(1);
    state.on_probe_acked(1, STEP_THRESHOLD);
    state.on_icmp_reduction(1250);
    assert_eq!(state.floor(), 1250);
    assert_eq!(state.phase(), PmtuPhase::Searching);
    assert_eq!(state.current_mtu(), 1250);
}

#[test]
fn pmtu_icmp_below_1200_clamps() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    state.on_icmp_reduction(800);
    assert_eq!(state.floor(), DEFAULT_FLOOR);
    assert_eq!(state.current_mtu(), DEFAULT_FLOOR);
}

#[test]
fn pmtu_reprobe_resets_ceiling() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    for _ in 0..10 {
        let pn = 100;
        state.set_probe_pn(pn);
        let result = state.on_probe_acked(pn, STEP_THRESHOLD);
        if result.is_complete() {
            break;
        }
    }
    assert_eq!(state.phase(), PmtuPhase::SearchComplete);
    state.start_reprobing(DEFAULT_CEILING);
    assert_eq!(state.phase(), PmtuPhase::Searching);
    assert_eq!(state.ceiling(), DEFAULT_CEILING);
    assert!(state.floor() > DEFAULT_FLOOR);
}

#[test]
fn pmtu_icmp_reduction_lowers_ceiling() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    state.on_icmp_reduction(1400);
    assert_eq!(state.ceiling(), 1400);
    assert_eq!(state.phase(), PmtuPhase::Searching);
}

#[test]
fn pmtu_icmp_does_nothing_if_above_ceiling() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    state.on_icmp_reduction(1500);
    assert_eq!(state.ceiling(), DEFAULT_CEILING);
}

#[test]
fn pmtu_binary_search_iterations() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    let mut iterations = 0;
    loop {
        iterations += 1;
        let pn = iterations as u64;
        state.set_probe_pn(pn);
        let result = state.on_probe_acked(pn, STEP_THRESHOLD);
        if result.is_complete() {
            break;
        }
        assert!(iterations <= 10, "search should converge");
    }
    assert!(
        iterations <= 5,
        "expected at most 5 iterations, got {}",
        iterations
    );
    assert_eq!(state.phase(), PmtuPhase::SearchComplete);
}
