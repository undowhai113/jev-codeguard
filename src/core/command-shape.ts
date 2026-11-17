/**
 * Detects whether a `jev_guard_action` exact_command is a literal command line or a
 * prose description of intent. In the real event log most guard inputs were prose
 * ("Commit only four documentation files ... read-only ..."), so Jev scored the
 * agent's self-description instead of the command it then executed.
 *
 * Pure and deterministic; quoted strings, here-strings and heredocs are ignored so
 * commit messages or inline scripts never count as prose.
 */

export interface CommandShapeAssessment {
  looksLikeProse: boolean;
  /** Short machine-readable reasons, e.g. "capitalized-lead:Commit". */
  signals: string[];
  /** Plain alphabetic words found outside quotes. */
  wordCount: number;
}

/** English function words that are common in prose and rare as bare shell arguments. */
const PROSE_STOPWORDS = new Set([
  "the", "a", "an", "and", "or", "but", "only", "into", "onto", "with", "without",
  "before", "after", "using", "via", "exactly", "that", "which", "this", "these",
  "those", "will", "would", "should", "must", "could", "is", "are", "was", "were",
  "be", "been", "no", "any", "every", "each", "of", "to", "from", "by", "as", "so",
  "because", "while", "also", "just", "then", "than", "it", "its", "we", "our",
  "you", "your", "their", "them", "against", "through", "per", "unless", "until"
]);

const MAX_ANALYZED_CHARS = 20000;
const MIN_WORDS_FOR_LEAD_SIGNAL = 3;
const STOPWORD_MIN_COUNT = 3;
const STOPWORD_MIN_RATIO = 0.15;
const WORD_RUN_MIN = 6;

const SINGLE_QUOTE_OPENERS = /[\s=(,;|&:{@[]/;

/** Removes string literals and comments so only the command's own words remain. */
function stripLiterals(command: string): string {
  const pre = command
    // PowerShell here-strings: the terminator '@ / "@ must start a line, so inner
    // text such as require('@prisma/client') does not end the literal early.
    .replace(/@'[ \t]*\r?\n[\s\S]*?\r?\n[ \t]*'@/g, " ")
    .replace(/@"[ \t]*\r?\n[\s\S]*?\r?\n[ \t]*"@/g, " ")
    // POSIX heredocs: <<EOF ... EOF, <<'EOF' ... EOF, <<-EOF ... EOF
    .replace(/<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1[\s\S]*?\n\s*\2(?=\s|$)/g, " ")
    // PowerShell block comments and full-line comments (PowerShell/bash)
    .replace(/<#[\s\S]*?#>/g, " ")
    .replace(/^[ \t]*#.*$/gm, " ");

  // Quote scanner: handles nesting like Trim('"') and PowerShell '' escapes, which a
  // pair of regexes cannot. Content inside quotes is dropped.
  let out = "";
  let quote: "'" | '"' | null = null;
  let quoteStart = -1;
  for (let i = 0; i < pre.length; i += 1) {
    const ch = pre[i];
    if (quote === null) {
      if (ch === '"') {
        quote = '"';
        quoteStart = i;
        out += " ";
      } else if (ch === "'" && (i === 0 || SINGLE_QUOTE_OPENERS.test(pre[i - 1]))) {
        // Apostrophes inside words ("Gemini's") never open a quote.
        quote = "'";
        quoteStart = i;
        out += " ";
      } else {
        out += ch;
      }
      continue;
    }
    if (quote === '"') {
      if (ch === "\\" || ch === "`") {
        i += 1;
      } else if (ch === '"') {
        quote = null;
      }
      continue;
    }
    if (ch === "'") {
      if (pre[i + 1] === "'") {
        i += 1; // PowerShell escaped quote inside a single-quoted string
      } else {
        quote = null;
      }
    }
  }
  if (quote !== null) {
    // Unterminated quote: treat the remainder as plain text rather than hiding it.
    out += pre.slice(quoteStart + 1);
  }
  return out;
}

const WORD_RE = /^[A-Za-z][A-Za-z'’-]*[,.:;!?]?$/;
const CAPITALIZED_PROSE_LEAD_RE = /^[A-Z][a-z]+(?:-[a-z]+)*[,:.]?$/;

function bareWord(token: string): string {
  return token.replace(/[,.:;!?]+$/, "").toLowerCase();
}

export function assessCommandShape(rawCommand: string): CommandShapeAssessment {
  const command = (rawCommand ?? "").slice(0, MAX_ANALYZED_CHARS).trim();
  if (command.length === 0) {
    return { looksLikeProse: true, signals: ["empty"], wordCount: 0 };
  }

  const stripped = stripLiterals(command);
  const tokens = stripped.split(/[\s;|&(){}<>]+/).filter((tok) => tok.length > 0);
  const signals: string[] = [];

  let wordCount = 0;
  let stopwordCount = 0;
  let run = 0;
  let runHasStopword = false;
  let longestProseRun = 0;
  for (const tok of tokens) {
    if (WORD_RE.test(tok)) {
      wordCount += 1;
      run += 1;
      if (PROSE_STOPWORDS.has(bareWord(tok))) {
        stopwordCount += 1;
        runHasStopword = true;
      }
      if (runHasStopword) longestProseRun = Math.max(longestProseRun, run);
    } else {
      run = 0;
      runHasStopword = false;
    }
  }

  const lead = tokens[0] ?? "";
  if (CAPITALIZED_PROSE_LEAD_RE.test(lead) && wordCount >= MIN_WORDS_FOR_LEAD_SIGNAL) {
    // PowerShell cmdlets are Verb-Noun with a capital noun (Get-Content) and never match.
    signals.push(`capitalized-lead:${lead.replace(/[,:.]+$/, "")}`);
  }
  if (stopwordCount >= STOPWORD_MIN_COUNT && stopwordCount / Math.max(1, wordCount) >= STOPWORD_MIN_RATIO) {
    signals.push(`stopwords:${stopwordCount}/${wordCount}`);
  }
  if (/[a-z]{2,}[.!?]\s+[A-Z][a-z]+\s/.test(stripped)) {
    signals.push("sentence-break");
  }
  if (/,\s+(?:and\s+)?(?:then|but|so)\s/i.test(stripped) || /\b(?:and then|followed by)\b/i.test(stripped)) {
    signals.push("prose-connector");
  }
  if (longestProseRun >= WORD_RUN_MIN) {
    signals.push(`word-run:${longestProseRun}`);
  }

  return { looksLikeProse: signals.length > 0, signals, wordCount };
}
