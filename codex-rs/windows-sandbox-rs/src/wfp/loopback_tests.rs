use super::blocked_tcp_ports;
use pretty_assertions::assert_eq;

#[test]
fn proxy_port_complement_handles_boundaries_duplicates_and_adjacent_ports() {
    for (allowed, expected) in [
        (vec![], vec![(1, u16::MAX)]),
        (vec![0, 1, u16::MAX], vec![(2, u16::MAX - 1)]),
        (vec![8081, 8080, 8080], vec![(1, 8079), (8082, u16::MAX)]),
        ((1..=u16::MAX).collect(), vec![]),
    ] {
        assert_eq!(blocked_tcp_ports(&allowed), expected, "{allowed:?}");
    }
}
