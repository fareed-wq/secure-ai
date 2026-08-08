import { REMEDIATION_SNIPPETS } from './src/lib/remediationSnippets.js';

let allValid = true;
let totalSnippets = 0;

for (const [finding, snippets] of Object.entries(REMEDIATION_SNIPPETS)) {
    if (!Array.isArray(snippets)) {
        console.error(`❌ [${finding}] is not an array.`);
        allValid = false;
        continue;
    }
    if (snippets.length === 0) {
        console.warn(`⚠️ [${finding}] has an empty array of snippets.`);
    }
    
    snippets.forEach((snippet, index) => {
        totalSnippets++;
        if (!snippet.platform) {
            console.error(`❌ [${finding}] Snippet at index ${index} is missing a 'platform'.`);
            allValid = false;
        }
        if (!snippet.code) {
            console.error(`❌ [${finding}] Snippet at index ${index} is missing 'code'.`);
            allValid = false;
        }
        // Basic syntax checking for Nginx snippets
        if (snippet.platform === 'Nginx' && snippet.code.includes('add_header') && !snippet.code.endsWith(';')) {
            console.warn(`⚠️ [${finding}] Nginx snippet might be missing a trailing semicolon: \n${snippet.code}`);
        }
    });
}

if (allValid) {
    console.log(`✅ Success: All ${Object.keys(REMEDIATION_SNIPPETS).length} mapped findings have properly formatted snippet arrays.`);
    console.log(`✅ Success: Total of ${totalSnippets} individual remediation snippets validated for structural integrity.`);
} else {
    console.error(`❌ Validation failed. See errors above.`);
    process.exit(1);
}
