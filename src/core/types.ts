export type JevQuestionType = "noul" | "choice" | "score";

export interface NoulQuestion {
  type: "noul";
  instructions: string;
  criteria?: unknown;
}

export interface ChoiceQuestion {
  type: "choice";
  instructions: string;
  criteria: Record<string, string>;
}

export interface ScoreQuestion {
  type: "score";
  instructions: string;
  criteria?: string[] | Record<string, string>;
}

export type JevQuestion = NoulQuestion | ChoiceQuestion | ScoreQuestion;

export interface JevRequest {
  model: string;
  state: unknown;
  questions: Record<string, JevQuestion>;
}

export interface NoulAnswer {
  type: "noul";
  noul: number;
}

export interface ChoiceAnswer {
  type: "choice";
  choice?: string;
  selected: string;
  confidence?: number;
  probabilities: Record<string, number>;
}

export interface ScoreAnswer {
  type: "score";
  score: number;
  confidence?: number;
  legend?: Record<string, string>;
  probabilities: Record<string, number>;
}

export type JevAnswer = NoulAnswer | ChoiceAnswer | ScoreAnswer;

export interface JevUsage {
  input_tokens: number;
  output_tokens: number;
  cost: number;
}

export interface JevResponse {
  model: string;
  answers: Record<string, JevAnswer>;
  usage?: JevUsage;
  provider?: string;
}

export type GateVerdict = "ALLOW" | "ASK_USER" | "BLOCK";

// Gate thresholds live in ./policy-config.ts (JEV_POLICY).

export interface PolicyDecision {
  verdict: GateVerdict;
  confidence: number;
  summary: string;
  reasons: string[];
  remediation: string[];
  metrics: Record<string, number | string>;
}

export type CodeStack =
  | "nextjs"
  | "express"
  | "react"
  | "vue"
  | "frontend"
  | "fastapi"
  | "django"
  | "flask"
  | "golang"
  | "gsap"
  | "general";

export interface SkillRemediationExcerpt {
  vector: string;
  probability: number;
  skillFile: string;
  title: string;
  excerpt: string;
}

export interface SkillAuditResult {
  stack: CodeStack;
  verdict: GateVerdict;
  /** Human-readable explanation that always matches `verdict`. */
  summary: string;
  securityScore: number;
  violatedVectors: Array<{ vector: string; probability: number; description: string }>;
  cleanVectors: string[];
  skillExcerpts: SkillRemediationExcerpt[];
  rawAnswers: Record<string, JevAnswer>;
  latencyMs: number;
  cached: boolean;
  usage?: JevUsage;
}
