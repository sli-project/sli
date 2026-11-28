import type { StationHardware } from "./hardware-model";

export const hardwareFixture: StationHardware = {
  observed_at: "2026-11-25T11:00:00Z",
  inventory: {
    computer: [{ id: "computer", manufacturer: "Example Systems", model: "Atlas 240", serial: "TEST-240-001" }],
    bios: [{ id: "bios", version: "1.15", date: "2026-11-19" }],
    security: [{ id: "security", secure_boot: true, tpm_enabled: true, tpm_version: "2.0" }],
    processor: [{ id: "cpu-1", model: "Example CPU 9700", cores: 8, threads: 16 }],
    memory: [{ id: "memory", size: 34359738368 }],
    memory_module: [
      { id: "ram-1", slot: "DIMM A2", size: 17179869184, speed: 5600, manufacturer: "Example Memory" },
      { id: "ram-2", slot: "DIMM B2", size: 17179869184, speed: 5600, manufacturer: "Example Memory" },
    ],
    disk: [
      { id: "disk-1", model: "Example SSD 512", size: 512000000000, type: "SSD", interface: "NVMe", serial: "TEST-SSD-001" },
      { id: "disk-2", model: "Example SSD 1000", size: 1000000000000, type: "SSD", interface: "NVMe", serial: "TEST-SSD-002" },
    ],
    volume: [
      { id: "volume-1", disk_id: "disk-1", mount: "C:", system: true, bitlocker: "on" },
      { id: "volume-2", disk_id: "disk-2", mount: "D:", system: false, bitlocker: "off" },
    ],
    video: [{ id: "video-1", model: "Example Graphics 780" }],
    network: [{ id: "network-1", name: "Example Ethernet", mac: "02:00:00:00:00:01", speed: 2500000000 }],
    monitor: [
      { id: "monitor-1", model: "Example Display 27", serial: null },
      { id: "monitor-2", model: "Example Display 24", serial: "TEST-DISPLAY-002" },
    ],
  },
  changes: [
    { id: "1", time: "2026-11-25T11:00:00Z", section: "disk", component_id: "disk-2", component: "Example SSD 1000",
      kind: "added", field: null, before: null, after: "Example SSD 1000", severity: "medium" },
    { id: "2", time: "2026-11-25T10:45:00Z", section: "memory", component_id: "memory", component: null,
      kind: "changed", field: "size", before: 17179869184, after: 34359738368, severity: "low" },
    { id: "3", time: "2026-11-25T10:30:00Z", section: "bios", component_id: "bios", component: null,
      kind: "version_changed", field: "version", before: "1.12", after: "1.15", severity: "low" },
  ],
};
