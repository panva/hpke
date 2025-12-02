import { chromium, firefox, webkit } from 'playwright'
import { spawn } from 'node:child_process'

const PORT = 3000
const testUrls = [
  new URL(`http://localhost:${PORT}/?ci&native`),
  new URL(`http://localhost:${PORT}/?ci&noble`),
  new URL(`http://localhost:${PORT}/?ci`),
]

// Start the server
function startServer() {
  return new Promise((resolve, reject) => {
    const server = spawn('npx', ['serve', '-l', String(PORT), '-n', '-L'], { stdio: 'pipe' })

    let started = false

    server.stdout.on('data', (data) => {
      const output = data.toString()
      if (output.includes('Accepting connections')) {
        if (!started) {
          started = true
          console.log('✓ Server started on port', PORT)
          resolve(server)
        }
      }
    })

    server.stderr.on('data', (data) => {
      console.error('Server error:', data.toString())
    })

    server.on('error', (error) => {
      reject(error)
    })

    // Timeout after 10 seconds
    setTimeout(() => {
      if (!started) {
        reject(new Error('Server failed to start within 10 seconds'))
      }
    }, 10000)
  })
}

// Wait for tests to complete on a page
async function waitForTestsToComplete(page, browserName, timeout = 180000) {
  console.log(`    Waiting for tests to complete in ${browserName}...`)

  try {
    // Wait for main algorithm tests
    await page.waitForFunction(
      () => {
        const results = globalThis.hpkeTestResults
        if (!results) return false
        const pending = results.total - results.passed - results.failed
        return pending === 0
      },
      { timeout },
    )

    // Wait for vector validation to complete
    await page.waitForFunction(
      () => {
        const results = globalThis.hpkeTestResults
        if (!results || !results.vectorValidation) return false
        return true
      },
      { timeout: 120000 },
    )

    const results = await page.evaluate(() => globalThis.hpkeTestResults)
    return results
  } catch (error) {
    console.error(`  ✗ Timeout waiting for tests in ${browserName}`)
    throw error
  }
}

// Run tests in a specific browser
async function runBrowserTests(browserType, browserName, channel = null) {
  console.log(`\nTesting with ${browserName}...`)

  const launchOptions = channel ? { channel } : {}
  const browser = await browserType.launch(launchOptions)
  const results = []

  for (const testUrl of testUrls) {
    const urlLabel = testUrl.search
    console.log(`\n  Testing ${urlLabel}`)

    const context = await browser.newContext()
    const page = await context.newPage()

    // Set default timeout for all page operations
    page.setDefaultTimeout(180000)

    // Listen for console messages
    page.on('console', (msg) => {
      const type = msg.type()
      if (type === 'error') {
        console.log(`  [${browserName} console.error]:`, msg.text())
      }
    })

    // Listen for page errors
    page.on('pageerror', (error) => {
      console.error(`  [${browserName} page error]:`, error.message)
    })

    try {
      await page.goto(testUrl.href, { waitUntil: 'networkidle' })

      const userAgent = await page.evaluate(() => navigator.userAgent)
      console.log(`  User Agent: ${userAgent}`)

      const testResults = await waitForTestsToComplete(page, browserName)

      console.log(`    Total tests: ${testResults.total}`)
      console.log(`    Passed: ${testResults.passed}`)
      console.log(`    Failed: ${testResults.failed}`)
      console.log(`    Expected failures: ${testResults.expectedFailures}`)
      console.log(`    Unexpected failures: ${testResults.unexpectedFailures}`)
      console.log(`    Unexpected passes: ${testResults.unexpectedPasses}`)

      if (testResults.vectorValidation) {
        console.log(
          `    Vector validation: ${testResults.vectorValidation.passed}/${testResults.vectorValidation.total} passed`,
        )
      }

      // Check for unexpected results
      if (testResults.unexpectedFailures > 0) {
        console.error(
          `\n    ✗ ${browserName} (${urlLabel}): ${testResults.unexpectedFailures} unexpected failure(s)!`,
        )
        console.error('\n    Failed tests:')
        testResults.tests
          .filter((t) => t.status === 'failed' && !t.expectedToFail)
          .forEach((t) => {
            console.error(`      - ${t.name}`)
            console.error(`        ${t.error}`)
          })
        results.push({ browserName, urlLabel, success: false, results: testResults })
      } else if (testResults.vectorValidation && testResults.vectorValidation.failed > 0) {
        console.error(
          `\n    ✗ ${browserName} (${urlLabel}): ${testResults.vectorValidation.failed} vector validation failure(s)!`,
        )
        results.push({ browserName, urlLabel, success: false, results: testResults })
      } else if (testResults.unexpectedPasses > 0) {
        console.error(
          `\n    ✗ ${browserName} (${urlLabel}): ${testResults.unexpectedPasses} unexpected pass(es)!`,
        )
        console.error(
          '\n    These tests were expected to fail but passed (browser support may have improved):',
        )
        testResults.tests
          .filter((t) => t.status === 'passed' && t.expectedToFail)
          .forEach((t) => {
            console.error(`      - ${t.name}`)
          })
        results.push({ browserName, urlLabel, success: false, results: testResults })
      } else {
        results.push({ browserName, urlLabel, success: true, results: testResults })
      }
    } catch (error) {
      console.error(`\n    ✗ ${browserName} (${urlLabel}): Error running tests:`, error.message)
      results.push({ browserName, urlLabel, success: false, error: error.message })
    } finally {
      await context.close()
    }
  }

  await browser.close()
  return results
}

// Main execution
async function main() {
  let server = null
  let exitCode = 0

  try {
    console.log('Starting server...')
    server = await startServer()

    const allBrowsers = [
      { type: chromium, name: 'Chromium' },
      { type: firefox, name: 'Firefox' },
      { type: webkit, name: 'Safari' },
    ]

    // Filter browsers based on BROWSER env var if set
    const browsers = process.env.BROWSER
      ? allBrowsers.filter((b) => b.name.toLowerCase() === process.env.BROWSER.toLowerCase())
      : allBrowsers

    if (browsers.length === 0) {
      throw new Error(`Unknown browser: ${process.env.BROWSER}`)
    }

    // Run tests sequentially to avoid resource issues
    const results = []
    const skipped = []
    for (const browser of browsers) {
      try {
        const browserResults = await runBrowserTests(browser.type, browser.name, browser.channel)
        results.push(...browserResults)
      } catch (error) {
        console.log(`\n  ⚠ Skipping ${browser.name}: ${error.message}`)
        for (const testUrl of testUrls) {
          skipped.push({ browserName: browser.name, urlLabel: testUrl.href, error: error.message })
        }
      }
    }

    // Summary
    console.log('\n' + '='.repeat(80))
    console.log('BROWSER TEST SUMMARY')
    console.log('='.repeat(80))

    const failed = results.filter((r) => !r.success)
    const passed = results.filter((r) => r.success)

    // Group results by browser
    const browserNames = [...new Set(results.map((r) => r.browserName))]
    for (const browserName of browserNames) {
      const browserResults = results.filter((r) => r.browserName === browserName)
      const browserSkipped = skipped.filter((r) => r.browserName === browserName)
      console.log(`\n${browserName}:`)
      browserResults.forEach((r) => {
        const status = r.success ? '✓' : '✗'
        console.log(`  ${status} ${r.urlLabel}`)
      })
      browserSkipped.forEach((r) => {
        console.log(`  ⚠ ${r.urlLabel}: SKIPPED`)
      })
    }

    // Also show any browsers that were entirely skipped
    const skippedBrowsers = [...new Set(skipped.map((r) => r.browserName))].filter(
      (name) => !browserNames.includes(name),
    )
    for (const browserName of skippedBrowsers) {
      const browserSkipped = skipped.filter((r) => r.browserName === browserName)
      console.log(`\n${browserName}:`)
      browserSkipped.forEach((r) => {
        console.log(`  ⚠ ${r.urlLabel}: SKIPPED`)
      })
    }

    if (failed.length > 0 || skipped.length > 0) {
      console.log(`\n${failed.length} failed, ${skipped.length} skipped, ${passed.length} passed`)
      exitCode = 1
    } else {
      console.log(`\nAll ${browserNames.length} browsers passed!`)
    }
  } catch (error) {
    console.error('\nFatal error:', error)
    exitCode = 1
  } finally {
    // Clean up server
    if (server) {
      console.log('\nStopping server...')
      server.kill()
    }
  }

  process.exit(exitCode)
}

main()
