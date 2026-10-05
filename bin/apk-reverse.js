#!/usr/bin/env node

/**
 * apk-reverse — Node.js CLI & npx runner
 * 
 * Jembatan executable untuk menjalankan apk_cli.py dan semua modul
 * reverse engineering Android langsung via `npx apk-reverse` atau `npm i -g apk-reverse`.
 * 
 * Dimodifikasi oleh ALDY.
 */

const { spawn, spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const ROOT_DIR = path.resolve(__dirname, '..');
const CLI_PATH = path.join(ROOT_DIR, 'apk_cli.py');
const SKILLS_DIR = path.join(ROOT_DIR, 'skills');

// Deteksi executable Python yang tersedia di sistem
function findPython() {
  // 1. Cek virtual environment lokal jika ada (.venv atau venv)
  const venvPaths = [
    path.join(ROOT_DIR, '.venv', 'Scripts', 'python.exe'),
    path.join(ROOT_DIR, 'venv', 'Scripts', 'python.exe'),
    path.join(ROOT_DIR, '.venv', 'bin', 'python'),
    path.join(ROOT_DIR, 'venv', 'bin', 'python')
  ];

  for (const p of venvPaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }

  // 2. Cek perintah di sistem: python3, python, py
  const candidates = process.platform === 'win32' 
    ? ['python', 'python3', 'py'] 
    : ['python3', 'python'];

  for (const cmd of candidates) {
    try {
      const res = spawnSync(cmd, ['--version'], { encoding: 'utf-8', stdio: 'pipe' });
      if (res.status === 0) {
        return cmd;
      }
    } catch (e) {
      // lanjut cek kandidat berikutnya
    }
  }

  return null;
}

// Handler khusus perintah list skill bawaan
function handleSkillsList() {
  console.log('\n📦 APK-REVERSE — DAFTAR SKILL AGENT TERSEDIA:');
  console.log('   (Dimodifikasi oleh ALDY)');
  console.log('═'.repeat(60));
  
  if (!fs.existsSync(SKILLS_DIR)) {
    console.error('❌ Folder skills tidak ditemukan di:', SKILLS_DIR);
    process.exit(1);
  }

  const items = fs.readdirSync(SKILLS_DIR, { withFileTypes: true });
  for (const item of items) {
    if (item.isDirectory()) {
      const skillMd = path.join(SKILLS_DIR, item.name, 'SKILL.md');
      let desc = '(Tidak ada deskripsi)';
      if (fs.existsSync(skillMd)) {
        const content = fs.readFileSync(skillMd, 'utf-8');
        const match = content.match(/description:\s*"([^"]+)"/);
        if (match) {
          desc = match[1];
        }
      }
      console.log(` • \x1b[36m${item.name}\x1b[0m`);
      console.log(`   ${desc}\n`);
    }
  }
  console.log('Cara pasang ke AI Agent Anda:');
  console.log('  \x1b[32mnpx skills add newliver666/apk-reverse\x1b[0m\n');
}

function main() {
  const args = process.argv.slice(2);

  // Perintah pembantu khusus npx
  if (args.length === 1 && (args[0] === '--skills' || args[0] === 'skills' || args[0] === 'list-skills')) {
    handleSkillsList();
    process.exit(0);
  }

  const pythonCmd = findPython();
  if (!pythonCmd) {
    console.error('\n\x1b[31m[ERROR] Python 3.9+ tidak ditemukan di sistem Anda.\x1b[0m');
    console.error('apk-reverse membutuhkan runtime Python untuk menjalankan tool analisis.');
    console.error('\nSolusi:');
    console.error(' 1. Unduh dan install Python dari: https://www.python.org/downloads/');
    console.error(' 2. Pastikan opsi "Add Python to PATH" dicentang saat instalasi.');
    console.error(' 3. Jalankan kembali: npx apk-reverse doctor\n');
    process.exit(1);
  }

  if (!fs.existsSync(CLI_PATH)) {
    console.error(`\n\x1b[31m[ERROR] File utama CLI tidak ditemukan:\x1b[0m ${CLI_PATH}`);
    process.exit(1);
  }

  // Teruskan semua argumen langsung ke apk_cli.py
  const child = spawn(pythonCmd, [CLI_PATH, ...args], {
    cwd: ROOT_DIR,
    stdio: 'inherit',
    env: { ...process.env, PYTHONIOENCODING: 'utf-8' }
  });

  child.on('error', (err) => {
    console.error('\n\x1b[31m[ERROR] Gagal menjalankan apk-reverse:\x1b[0m', err.message);
    process.exit(1);
  });

  child.on('close', (code) => {
    process.exit(code ?? 0);
  });

  // Handle Ctrl+C
  process.on('SIGINT', () => {
    child.kill('SIGINT');
  });
  process.on('SIGTERM', () => {
    child.kill('SIGTERM');
  });
}

main();
