#!/usr/bin/env node
/**
 * Cloudflare Multi-Tier Scraping Pipeline
 * Direct implementation modeled after C:\streming-anime\backend\src\helpers\getHTML.ts
 *
 * PIPELINE ORDER:
 * 1. Step CF-Worker (if CF_WORKER_URL env is set)
 * 2. Step got-scraping (HTTP/2 + TLS Browser Fingerprint)
 * 3. Step Puppeteer-Extra Stealth / Puppeteer-Real-Browser
 */

import fs from 'fs';
import path from 'path';

const userAgent =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36';

function isCloudflareBlocked(html) {
  if (!html || !html.trim()) return true;

  const lower = html.toLowerCase();
  const isChallengeTitle =
    lower.includes('<title>just a moment') ||
    lower.includes('<title>attention required') ||
    lower.includes('<title>tunggu sebentar');

  // If HTML length > 30KB and no challenge title, assume not blocked
  if (html.length > 30000 && !isChallengeTitle) {
    return false;
  }

  const indicators = [
    'Just a moment...',
    'Tunggu sebentar...',
    'Attention Required!',
    'cf-browser-verification',
    'cf-challenge-running',
    'Sorry, you have been blocked',
    'cf-turnstile',
    'Enable JavaScript and cookies to continue',
    'cf_chl_opt',
    'challenge-error-title',
  ];

  return indicators.some((indicator) => html.includes(indicator));
}

async function fetchWithWorker(targetUrl, workerBaseUrl) {
  const workerUrl = `${workerBaseUrl.replace(/\/+$/, '')}?url=${encodeURIComponent(targetUrl)}`;
  console.log(`[Pipeline] Step 0 (CF-Worker): ${workerUrl}`);
  const res = await fetch(workerUrl, {
    headers: { 'User-Agent': userAgent },
  });
  if (res.ok) {
    const html = await res.text();
    if (html && !isCloudflareBlocked(html)) {
      return html;
    }
  }
  return null;
}

async function fetchWithGotScraping(targetUrl) {
  console.log(`[Pipeline] Step 1 (got-scraping/TLS): ${targetUrl}`);
  try {
    const { gotScraping } = await import('got-scraping');
    const response = await gotScraping({
      url: targetUrl,
      headers: {
        'User-Agent': userAgent,
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      },
    });
    if (!isCloudflareBlocked(response.body)) {
      return response.body;
    }
    console.log('[Pipeline] Step 1 hit Cloudflare challenge');
  } catch (err) {
    console.warn(`[Pipeline] Step 1 failed or got-scraping not installed: ${err.message}`);
  }
  return null;
}

async function fetchWithPuppeteerStealth(targetUrl) {
  console.log(`[Pipeline] Step 2 (Puppeteer Stealth): ${targetUrl}`);
  try {
    const puppeteerExtra = (await import('puppeteer-extra')).default;
    const StealthPlugin = (await import('puppeteer-extra-plugin-stealth')).default;
    puppeteerExtra.use(StealthPlugin());

    const browser = await puppeteerExtra.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });

    try {
      const page = await browser.newPage();
      await page.setUserAgent(userAgent);

      // Block heavy resources
      await page.setRequestInterception(true);
      page.on('request', (req) => {
        const type = req.resourceType();
        if (['image', 'stylesheet', 'font', 'media'].includes(type)) {
          req.abort();
        } else {
          req.continue();
        }
      });

      await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await new Promise((r) => setTimeout(r, 3000));

      const content = await page.content();
      if (!isCloudflareBlocked(content)) {
        return content;
      }
    } finally {
      await browser.close();
    }
  } catch (err) {
    console.warn(`[Pipeline] Step 2 error or puppeteer-extra not installed: ${err.message}`);
  }
  return null;
}

async function main() {
  const args = process.argv.slice(2);
  let targetUrl = '';
  let outFile = '';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--help' || args[i] === '-h') {
      console.log('Usage: node cf_pipeline.js --url <URL> [--out <output_path>]');
      process.exit(0);
    }
    if (args[i] === '--url' && args[i + 1]) targetUrl = args[i + 1];
    if (args[i] === '--out' && args[i + 1]) outFile = args[i + 1];
  }

  if (!targetUrl) {
    console.log('Usage: node cf_pipeline.js --url <URL> [--out <output_path>]');
    process.exit(1);
  }

  console.log(`=== Starting Cloudflare Bypass Pipeline for: ${targetUrl} ===`);

  let html = null;

  // Step 0: CF Worker Edge Proxy
  if (process.env.CF_WORKER_URL) {
    html = await fetchWithWorker(targetUrl, process.env.CF_WORKER_URL);
    if (html) {
      console.log('[+] SUCCESS via Step 0 (CF-Worker Edge Proxy)');
    }
  }

  // Step 1: got-scraping
  if (!html) {
    html = await fetchWithGotScraping(targetUrl);
    if (html) {
      console.log('[+] SUCCESS via Step 1 (got-scraping / TLS Fingerprint)');
    }
  }

  // Step 2: Puppeteer Stealth
  if (!html) {
    html = await fetchWithPuppeteerStealth(targetUrl);
    if (html) {
      console.log('[+] SUCCESS via Step 2 (Puppeteer Stealth)');
    }
  }

  if (html) {
    if (outFile) {
      fs.writeFileSync(outFile, html, 'utf-8');
      console.log(`[+] Output successfully written to ${outFile} (${html.length} bytes)`);
    } else {
      console.log(`[+] Fetched ${html.length} bytes cleanly.`);
    }
    process.exit(0);
  } else {
    console.error('[-] Failed to bypass Cloudflare using available tiers.');
    process.exit(1);
  }
}

main();
