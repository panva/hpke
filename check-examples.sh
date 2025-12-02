#!/usr/bin/env bash
set -e

# Generate documentation
node --run docs

# Calculate the relative import path from a markdown file to index.ts
calculate_import_path() {
  local md_file="$1"
  local depth=$(echo "$md_file" | awk -F'/' '{print NF-1}')
  printf '../%.0s' $(seq 1 $depth)
}

# Extract TypeScript code blocks from markdown and write them as .ts files
extract_typescript_blocks() {
  local md_file="$1"
  local base_name="${md_file%.*}"
  local import_path="$(calculate_import_path "$md_file")index.ts"

  # Extract TypeScript code blocks from markdown as JSON array
  pandoc -i "$md_file" -t json |
    jq -a '.blocks[] | select(.t == "CodeBlock" and .c[0][1][0] == "ts") | .c[1]' |
    jq -s >"${base_name}.tmp"

  # Convert each code block to a standalone TypeScript file
  node <<-EOF
    const fs = require('node:fs');
    const codeBlocks = JSON.parse(fs.readFileSync('${base_name}.tmp', 'ascii'));

    codeBlocks.forEach((code, index) => {
      const hasImport = code.includes('import * as HPKE');
      const content = hasImport
        ? code.replace('hpke', '${import_path}')
        : \`import * as HPKE from '${import_path}'\n\n\${code}\`;

      fs.writeFileSync(\`${base_name}.\${index}.ts\`, content);
    });
EOF

  rm "${base_name}.tmp"
}

# Process all markdown files in docs
for file in docs/README.md docs/**/*.md; do
  extract_typescript_blocks "$file"
done

# Type-check extracted examples and clean up
tsc -p tsconfig.docs.json && rm docs/**/*.ts docs/*.ts
