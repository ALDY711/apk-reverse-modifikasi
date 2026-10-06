# Canvas 2D, WebGL/WebGPU, & AudioContext Fingerprinting Deep Dive

This technical reference provides an exhaustive mathematical and architectural analysis of hardware-level browser fingerprinting vectors: **Canvas 2D sub-pixel rendering**, **WebGL/WebGPU shader compilation**, and **AudioContext DSP frequency response**.

---

## 1. Canvas 2D Sub-Pixel Font Rasterization

When a browser renders text to an HTML5 `<canvas>` element, the rasterized bitmap varies across operating systems and GPU drivers due to font hinting and sub-pixel anti-aliasing algorithms:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Canvas Sub-Pixel Rendering Differences               │
├───────────────────┬───────────────────┬────────────────────────────────┤
│ Operating System  │ Font Engine       │ Anti-Aliasing Technique        │
├───────────────────┼───────────────────┼────────────────────────────────┤
│ **Windows 10/11** │ DirectWrite / GDI │ Sub-pixel ClearType (RGB/BGR)  │
│ **macOS**         │ CoreText          │ Grayscale smoothing (Dilation) │
│ **Linux**         │ FreeType / Cairo  │ Sub-pixel LCD filtering        │
└───────────────────┴───────────────────┴────────────────────────────────┘
```

### Typical Cloudflare Canvas Probe String:
```javascript
const canvas = document.createElement('canvas');
canvas.width = 200; canvas.height = 50;
const ctx = canvas.getContext('2d');
ctx.textBaseline = 'top';
ctx.font = '14px Arial';
ctx.textBaseline = 'alphabetic';
ctx.fillStyle = '#f60';
ctx.fillRect(125, 1, 62, 20);
ctx.fillStyle = '#069';
ctx.fillText('Cwm fjordbank glyphs vext quiz, 😃', 2, 15);
ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
ctx.fillText('Cwm fjordbank glyphs vext quiz, 😃', 4, 17);
const canvasHash = canvas.toDataURL();
```

### The Pitfall of Canvas Noise Injection:
Many public anti-detect extensions randomly alter 1–2 pixels in the canvas buffer.
* **Why this fails:** Cloudflare executes mathematical consistency checks on gradient interpolations. Random noise breaks linear interpolation curves, signaling **synthetic tampering** and triggering immediate challenge failures.
* **Prescribed Action:** Maintain native OS rasterization (via XVFB on Linux) rather than injecting synthetic random noise.

---

## 2. WebGL 1.0/2.0 & WebGPU Driver Fingerprinting

Cloudflare probes the underlying GPU driver for rendering capabilities, shader precision, and extension support.

### Evaluated WebGL Parameters:
1. **Unmasked Vendor & Renderer:**
   ```javascript
   const dbg = gl.getExtension('WEBGL_debug_renderer_info');
   const vendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
   const renderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
   // Real Windows: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11)"
   // Virtualized Linux VPS: "Google SwiftShader" or "Mesa OffScreen" -> INSTANT BOT FLAG!
   ```
2. **Shader Compiler Float Precision:**
   Measures floating-point mantissa and exponent range:
   ```javascript
   gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT);
   ```
3. **Max Texture & Uniform Vectors:**
   - `MAX_TEXTURE_SIZE` (Real GPU = `16384` or `32768`, SwiftShader = `8192`)
   - `MAX_RENDERBUFFER_SIZE` (Real GPU = `16384`)

---

## 3. AudioContext DSP & DynamicsCompressor Frequency Decay

Audio fingerprinting does NOT record through a microphone. Instead, it measures subtle mathematical differences in how the CPU's Floating-Point Unit (FPU) computes digital audio signal processing (DSP) filters.

```
[OscillatorNode (Triangle Wave)] ──► [DynamicsCompressorNode] ──► [OfflineAudioContext Buffer]
                                                                          │
                                                                          ▼
                                                              [Float32Array Sum Checksum]
```

### Audio Fingerprint Algorithm:
```javascript
const audioCtx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 5000, 44100);
const osc = audioCtx.createOscillator();
osc.type = 'triangle';
osc.frequency.setValueAtTime(10000, audioCtx.currentTime);

const compressor = audioCtx.createDynamicsCompressor();
compressor.threshold.setValueAtTime(-50, audioCtx.currentTime);
compressor.knee.setValueAtTime(40, audioCtx.currentTime);
compressor.ratio.setValueAtTime(12, audioCtx.currentTime);
compressor.attack.setValueAtTime(0, audioCtx.currentTime);
compressor.release.setValueAtTime(0.25, audioCtx.currentTime);

osc.connect(compressor);
compressor.connect(audioCtx.destination);
osc.start(0);

audioCtx.startRendering().then(renderedBuffer => {
  const channelData = renderedBuffer.getChannelData(0);
  let sum = 0;
  for (let i = 0; i < channelData.length; i++) {
    sum += Math.abs(channelData[i]);
  }
  console.log('Audio DSP Checksum:', sum);
});
```

Because Intel x86-64, AMD Zen, ARM64 NEON, and Apple M-series processors handle floating-point rounding at the 7th decimal place ($10^{-7}$) slightly differently during complex IIR filtering, the resulting sum is a permanent **hardware architecture fingerprint**.
