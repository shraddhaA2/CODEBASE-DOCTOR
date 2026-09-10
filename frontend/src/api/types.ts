export type ScanStatus = 'queued' | 'running' | 'succeeded' | 'failed';

export interface LanguageFileItem {
  path: string;
  size: number;
  language: string;
  is_binary: boolean;
}

export interface LanguageStats {
  total_files: number;
  python_files: number;
  non_python_files: number;
  skipped_binary_files: number;
  total_size_bytes: number;
  language_counts: Record<string, number>;
  language_bytes: Record<string, number>;
  files: LanguageFileItem[];
}

export interface Scan {
  id: string;
  github_url: string;
  status: ScanStatus;
  error: string | null;
  commit_sha: string | null;
  created_at: string;
  language_stats: LanguageStats | null;
}

export type FindingCategory = 'bug' | 'security' | 'dead_code' | 'dependency' | 'architecture' | 'quality';
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  scan_id: string;
  analyzer: string;
  category: FindingCategory;
  severity: FindingSeverity;
  rule_id: string;
  file_path: string;
  start_line: number | null;
  end_line: number | null;
  message: string;
  evidence: Record<string, any> | null;
  redacted_snippet: string | null;
}

export interface ArchitectureMetric {
  id: string;
  scan_id: string;
  module: string;
  fan_in: number;
  fan_out: number;
  circular_component_id: number | null;
}

export interface ArchitectureHub {
  module: string;
  fan_in: number;
  fan_out: number;
}

export interface ArchitectureSummary {
  total_modules: number;
  total_dependencies: number;
  circular_components_count: number;
  hubs: ArchitectureHub[];
  metrics: ArchitectureMetric[];
}

export interface PenaltyItem {
  finding_id: string;
  rule_id: string;
  severity: string;
  penalty: number;
  file_path: string;
  start_line: number | null;
  message: string;
}

export interface DimensionAudit {
  starting_score: number;
  penalties: PenaltyItem[];
  total_penalty: number;
  final_score: number;
  weight: number;
  status?: string;
  explanation?: string;
}

export interface ScoreBreakdown {
  security: DimensionAudit;
  architecture: DimensionAudit;
  maintainability: DimensionAudit;
  performance: DimensionAudit;
  code_quality: DimensionAudit;
  dependencies: DimensionAudit;
  overall: {
    formula: string;
    inputs: Record<string, number>;
    weights: Record<string, number>;
    calculated_overall: number;
  };
}

export interface HealthScore {
  scan_id: string;
  security: number;
  architecture: number;
  maintainability: number;
  performance: number;
  code_quality: number;
  dependencies: number;
  overall: number;
  breakdown: ScoreBreakdown;
}

export interface DiagnosisItem {
  diagnosis: string;
  why_it_matters: string;
  impact: string;
  recommended_action: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  evidence_sufficient: boolean;
  related_finding_ids: string[];
}

export interface DiagnosisReport {
  summary: string;
  diagnoses: DiagnosisItem[];
}

export interface PatchProposal {
  id: string;
  scan_id: string;
  file_path: string;
  original: string;
  proposed: string;
  unified_diff: string;
  explanation: string;
  confidence: number;
  risk: 'low' | 'medium' | 'high';
  status: string;
}

export interface AiReport {
  id: string;
  scan_id: string;
  kind: 'diagnosis' | 'recommendations' | 'patch';
  validated_json: any;
  created_at: string;
}

export interface AiData {
  reports: AiReport[];
  patches: PatchProposal[];
}
