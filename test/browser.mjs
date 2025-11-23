import { chromium, firefox, webkit } from 'playwright'
import { spawn } from 'node:child_process'

const PORT = 3000
const URL = `http://localhost:${PORT}`

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
  console.log(`  Waiting for tests to complete in ${browserName}...`)

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
    await page.goto(URL, { waitUntil: 'networkidle' })

    const userAgent = await page.evaluate(() => navigator.userAgent)
    console.log(`  User Agent: ${userAgent}`)

    const results = await waitForTestsToComplete(page, browserName)

    console.log(`  Total tests: ${results.total}`)
    console.log(`  Passed: ${results.passed}`)
    console.log(`  Failed: ${results.failed}`)
    console.log(`  Expected failures: ${results.expectedFailures}`)
    console.log(`  Unexpected failures: ${results.unexpectedFailures}`)
    console.log(`  Unexpected passes: ${results.unexpectedPasses}`)

    if (results.vectorValidation) {
      console.log(
        `  Vector validation: ${results.vectorValidation.passed}/${results.vectorValidation.total} passed`,
      )
    }

    // Check for unexpected results
    if (results.unexpectedFailures > 0) {
      console.error(`\n  ✗ ${browserName}: ${results.unexpectedFailures} unexpected failure(s)!`)
      console.error('\n  Failed tests:')
      results.tests
        .filter((t) => t.status === 'failed' && !t.expectedToFail)
        .forEach((t) => {
          console.error(`    - ${t.name}`)
          console.error(`      ${t.error}`)
        })
      return { browserName, success: false, results }
    }

    if (results.vectorValidation && results.vectorValidation.failed > 0) {
      console.error(
        `\n  ✗ ${browserName}: ${results.vectorValidation.failed} vector validation failure(s)!`,
      )
      return { browserName, success: false, results }
    }

    if (results.unexpectedPasses > 0) {
      console.error(`\n  ✗ ${browserName}: ${results.unexpectedPasses} unexpected pass(es)!`)
      console.error(
        '\n  These tests were expected to fail but passed (browser support may have improved):',
      )
      results.tests
        .filter((t) => t.status === 'passed' && t.expectedToFail)
        .forEach((t) => {
          console.error(`    - ${t.name}`)
        })
      return { browserName, success: false, results }
    }
    return { browserName, success: true, results }
  } catch (error) {
    console.error(`\n  ✗ ${browserName}: Error running tests:`, error.message)
    return { browserName, success: false, error: error.message }
  } finally {
    await browser.close()
  }
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
        const result = await runBrowserTests(browser.type, browser.name, browser.channel)
        results.push(result)
      } catch (error) {
        console.log(`\n  ⚠ Skipping ${browser.name}: ${error.message}`)
        skipped.push({ browserName: browser.name, error: error.message })
      }
    }

    // Summary
    console.log('\n' + '='.repeat(80))
    console.log('BROWSER TEST SUMMARY')
    console.log('='.repeat(80))

    const failed = results.filter((r) => !r.success)
    const passed = results.filter((r) => r.success)

    passed.forEach((r) => {
      console.log(`✓ ${r.browserName}: PASSED`)
    })

    failed.forEach((r) => {
      console.log(`✗ ${r.browserName}: FAILED`)
    })

    skipped.forEach((r) => {
      console.log(`⚠ ${r.browserName}: SKIPPED`)
    })

    if (failed.length > 0 || skipped.length > 0) {
      console.log(
        `\n${failed.length} browser(s) failed, ${skipped.length} skipped, ${passed.length} passed`,
      )
      exitCode = 1
    } else {
      console.log(`\nAll ${passed.length} browser(s) passed!`)
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
