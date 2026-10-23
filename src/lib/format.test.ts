import { describe, expect, it } from "vitest";
import { formatBytes } from "./format";

const GiB = 1024 ** 3;

describe("formatBytes", () => {
  it("prints bytes below 1 KB as integers", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
  });

  it("switches unit at 1024", () => {
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
  });

  it("handles the GiB boundary without printing 1024.0 MB", () => {
    expect(formatBytes(GiB - 1)).toBe("1.0 GB");
    expect(formatBytes(GiB)).toBe("1.0 GB");
    expect(formatBytes(GiB * 196.96)).toBe("197.0 GB");
    expect(formatBytes(GiB - 200 * 1024 * 1024)).toBe("824.0 MB");
  });

  it("caps at TB", () => {
    expect(formatBytes(2048 * 1024 * GiB)).toBe("2048.0 TB");
  });
});
