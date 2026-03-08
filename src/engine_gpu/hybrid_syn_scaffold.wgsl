@group(0) @binding(0) var<storage, read_write> packet_words: array<u32>;

struct HybridScanParams {
    base_ip: u32,
    source_ip: u32,
    destination_port: u32,
    source_port: u32,
};

@group(0) @binding(1) var<uniform> params: HybridScanParams;

fn add_ones_complement(a: u32, b: u32) -> u32 {
    var sum = a + b;
    if (sum > 0xFFFFu) {
        sum = (sum & 0xFFFFu) + 1u;
    }
    return sum;
}

@compute @workgroup_size(64)
fn craft_syn_packets(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let idx = global_id.x;
    let target_ip = params.base_ip + idx;
    let base = idx * 10u;

    packet_words[base + 0u] = 0x45000028u;
    packet_words[base + 1u] = (idx & 0xFFFFu) << 16u;
    packet_words[base + 2u] = 0x40060000u;
    packet_words[base + 3u] = params.source_ip;
    packet_words[base + 4u] = target_ip;
    packet_words[base + 5u] =
        (params.source_port << 16u) | (params.destination_port & 0xFFFFu);
    packet_words[base + 6u] = idx * 7919u;
    packet_words[base + 7u] = 0u;
    packet_words[base + 8u] = 0x50020400u;
    packet_words[base + 9u] = 0u;

    var checksum: u32 = 0u;
    checksum = add_ones_complement(checksum, params.source_ip >> 16u);
    checksum = add_ones_complement(checksum, params.source_ip & 0xFFFFu);
    checksum = add_ones_complement(checksum, target_ip >> 16u);
    checksum = add_ones_complement(checksum, target_ip & 0xFFFFu);
    checksum = add_ones_complement(checksum, 0x0006u);
    checksum = add_ones_complement(checksum, 0x0014u);

    for (var i: u32 = 5u; i < 9u; i = i + 1u) {
        checksum = add_ones_complement(checksum, packet_words[base + i] >> 16u);
        checksum = add_ones_complement(checksum, packet_words[base + i] & 0xFFFFu);
    }

    let final_checksum = (~checksum) & 0xFFFFu;
    packet_words[base + 9u] = (final_checksum << 16u);
}
