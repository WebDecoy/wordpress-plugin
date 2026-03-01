<?php
/**
 * WebDecoy Behavioral Scorer
 *
 * Analyzes behavioral signals from client-side JavaScript to determine
 * if the visitor is human or automated. Scores across four categories:
 * behavioral (40%), environmental (35%), temporal (15%), form (10%).
 *
 * @package WebDecoy
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class WebDecoy_Behavioral_Scorer
{
    /**
     * Category weights (must sum to 1.0)
     */
    private const WEIGHTS = [
        'behavioral' => 0.40,
        'environmental' => 0.35,
        'temporal' => 0.15,
        'form' => 0.10,
    ];

    /**
     * Score behavioral signals from client
     *
     * @param array $signals Signals from client-side JS
     * @return array ['score' => float, 'category_scores' => array, 'detections' => array]
     */
    public function score(array $signals): array
    {
        $detections = [];

        $behavioral_score = $this->score_behavioral($signals['mouse'] ?? [], $signals['clicks'] ?? [], $signals['scroll'] ?? [], $detections);
        $environmental_score = $this->score_environmental($signals['environment'] ?? [], $detections);
        $temporal_score = $this->score_temporal($signals['timing'] ?? [], $detections);
        $form_score = $this->score_form_interaction($signals['form'] ?? [], $detections);

        $category_scores = [
            'behavioral' => $behavioral_score,
            'environmental' => $environmental_score,
            'temporal' => $temporal_score,
            'form' => $form_score,
        ];

        // Weighted average
        $total = 0.0;
        foreach ($category_scores as $category => $cat_score) {
            $total += $cat_score * self::WEIGHTS[$category];
        }

        return [
            'score' => round(min(1.0, max(0.0, $total)), 4),
            'category_scores' => $category_scores,
            'detections' => $detections,
        ];
    }

    /**
     * Score mouse + click + scroll behavior
     */
    private function score_behavioral(array $mouse, array $clicks, array $scroll, array &$detections): float
    {
        $score = 0.0;
        $signals_counted = 0;

        // Mouse movement analysis
        if (!empty($mouse)) {
            $signals_counted++;

            // Low velocity variance = robotic
            $velocity_variance = isset($mouse['velocityVariance']) ? (float) $mouse['velocityVariance'] : null;
            if ($velocity_variance !== null) {
                if ($velocity_variance < 0.1) {
                    $score += 0.9;
                    $detections[] = ['category' => 'behavioral', 'signal' => 'low_velocity_variance', 'confidence' => 0.8];
                } elseif ($velocity_variance < 1.0) {
                    $score += 0.4;
                }
            }

            // Straight line ratio (high = bot)
            $straight_line_ratio = isset($mouse['straightLineRatio']) ? (float) $mouse['straightLineRatio'] : null;
            if ($straight_line_ratio !== null) {
                if ($straight_line_ratio > 0.8) {
                    $score += 0.8;
                    $detections[] = ['category' => 'behavioral', 'signal' => 'straight_line_movement', 'confidence' => 0.7];
                } elseif ($straight_line_ratio > 0.5) {
                    $score += 0.3;
                }
            }

            // No micro-tremors (humans have 3-25Hz hand tremor)
            $micro_tremor = isset($mouse['microTremorScore']) ? (float) $mouse['microTremorScore'] : null;
            if ($micro_tremor !== null && $micro_tremor < 0.1) {
                $score += 0.6;
                $detections[] = ['category' => 'behavioral', 'signal' => 'no_micro_tremor', 'confidence' => 0.6];
            }

            // Few direction changes
            $direction_changes = (float) ($mouse['directionChanges'] ?? 0);
            $total_points = (float) ($mouse['totalPoints'] ?? 1);
            if ($total_points > 20 && $direction_changes < $total_points * 0.1) {
                $score += 0.5;
                $detections[] = ['category' => 'behavioral', 'signal' => 'few_direction_changes', 'confidence' => 0.5];
            }

            // No mouse movement at all
            if ($total_points < 5) {
                $score += 0.7;
                $detections[] = ['category' => 'behavioral', 'signal' => 'minimal_mouse_movement', 'confidence' => 0.6];
            }
        } else {
            // No mouse data at all = suspicious
            $signals_counted++;
            $score += 0.5;
            $detections[] = ['category' => 'behavioral', 'signal' => 'no_mouse_data', 'confidence' => 0.4];
        }

        // Click analysis
        if (!empty($clicks)) {
            $signals_counted++;
            $hold_duration = isset($clicks['holdDuration']) ? (float) $clicks['holdDuration'] : null;
            if ($hold_duration !== null) {
                // Perfect click timing (exactly same ms) = bot
                if ($hold_duration < 20) {
                    $score += 0.7;
                    $detections[] = ['category' => 'behavioral', 'signal' => 'instant_click', 'confidence' => 0.7];
                } elseif ($hold_duration > 2000) {
                    $score += 0.3;
                }
            }
        }

        // Scroll analysis
        if (!empty($scroll)) {
            $signals_counted++;
            $scroll_variance = isset($scroll['velocityVariance']) ? (float) $scroll['velocityVariance'] : null;
            if ($scroll_variance !== null && $scroll_variance < 0.05) {
                $score += 0.6;
                $detections[] = ['category' => 'behavioral', 'signal' => 'robotic_scrolling', 'confidence' => 0.6];
            }
        }

        return $signals_counted > 0 ? min(1.0, $score / $signals_counted) : 0.0;
    }

    /**
     * Score environmental signals
     */
    private function score_environmental(array $env, array &$detections): float
    {
        if (empty($env)) {
            return 0.0;
        }

        $score = 0.0;
        $checks = 0;

        // WebGL renderer consistency
        if (isset($env['webglRenderer'])) {
            $checks++;
            $renderer = strtolower($env['webglRenderer']);
            if (strpos($renderer, 'swiftshader') !== false || strpos($renderer, 'llvmpipe') !== false) {
                $score += 0.9;
                $detections[] = ['category' => 'environmental', 'signal' => 'software_renderer', 'confidence' => 0.9];
            }
        }

        // Canvas fingerprint present
        if (isset($env['canvasHash'])) {
            $checks++;
            if (empty($env['canvasHash']) || $env['canvasHash'] === '0') {
                $score += 0.6;
                $detections[] = ['category' => 'environmental', 'signal' => 'no_canvas_fingerprint', 'confidence' => 0.5];
            }
        }

        // Timezone/language mismatch
        if (isset($env['timezone']) && isset($env['language'])) {
            $checks++;
            // Basic mismatch detection
            if ($this->detect_locale_mismatch($env['timezone'], $env['language'])) {
                $score += 0.4;
                $detections[] = ['category' => 'environmental', 'signal' => 'locale_mismatch', 'confidence' => 0.4];
            }
        }

        // Navigator properties
        if (isset($env['plugins'])) {
            $checks++;
            if ((int) $env['plugins'] === 0) {
                $score += 0.5;
                $detections[] = ['category' => 'environmental', 'signal' => 'no_plugins', 'confidence' => 0.5];
            }
        }

        // Screen dimensions
        if (isset($env['screenWidth']) && isset($env['screenHeight'])) {
            $checks++;
            $w = (int) $env['screenWidth'];
            $h = (int) $env['screenHeight'];
            if ($w === 0 || $h === 0 || ($w === 800 && $h === 600)) {
                $score += 0.6;
                $detections[] = ['category' => 'environmental', 'signal' => 'suspicious_screen_size', 'confidence' => 0.5];
            }
        }

        return $checks > 0 ? min(1.0, $score / $checks) : 0.0;
    }

    /**
     * Score temporal signals
     */
    private function score_temporal(array $timing, array &$detections): float
    {
        if (empty($timing)) {
            return 0.0;
        }

        $score = 0.0;
        $checks = 0;

        // Time to first interaction
        $tti = isset($timing['timeToFirstInteraction']) ? (float) $timing['timeToFirstInteraction'] : null;
        if ($tti !== null) {
            $checks++;
            if ($tti < 100) { // < 100ms = almost certainly bot
                $score += 0.9;
                $detections[] = ['category' => 'temporal', 'signal' => 'instant_interaction', 'confidence' => 0.9];
            } elseif ($tti < 500) {
                $score += 0.4;
            }
        }

        // Event timing regularity (too regular = bot)
        $timing_variance = isset($timing['eventTimingVariance']) ? (float) $timing['eventTimingVariance'] : null;
        if ($timing_variance !== null) {
            $checks++;
            if ($timing_variance < 1.0) { // Nearly zero variance = perfectly timed
                $score += 0.8;
                $detections[] = ['category' => 'temporal', 'signal' => 'regular_timing', 'confidence' => 0.7];
            }
        }

        // Session duration
        $duration = isset($timing['sessionDuration']) ? (float) $timing['sessionDuration'] : null;
        if ($duration !== null) {
            $checks++;
            if ($duration < 500) { // < 500ms session
                $score += 0.7;
                $detections[] = ['category' => 'temporal', 'signal' => 'very_short_session', 'confidence' => 0.6];
            }
        }

        return $checks > 0 ? min(1.0, $score / $checks) : 0.0;
    }

    /**
     * Score form interaction signals
     */
    private function score_form_interaction(array $form, array &$detections): float
    {
        if (empty($form)) {
            return 0.0;
        }

        $score = 0.0;
        $checks = 0;

        // Time to submission
        $tts = isset($form['timeToSubmission']) ? (float) $form['timeToSubmission'] : null;
        if ($tts !== null) {
            $checks++;
            if ($tts < 2000) { // < 2s for a form = bot
                $score += 0.8;
                $detections[] = ['category' => 'form', 'signal' => 'fast_submission', 'confidence' => 0.8];
            } elseif ($tts < 5000) {
                $score += 0.3;
            }
        }

        // Programmatic submit detection
        if (!empty($form['programmaticSubmit'])) {
            $checks++;
            $score += 0.9;
            $detections[] = ['category' => 'form', 'signal' => 'programmatic_submit', 'confidence' => 0.9];
        }

        // Field focus count (no focus events = likely bot)
        $focus_count = isset($form['fieldFocusCount']) ? (float) $form['fieldFocusCount'] : null;
        if ($focus_count !== null) {
            $checks++;
            if ($focus_count == 0) {
                $score += 0.7;
                $detections[] = ['category' => 'form', 'signal' => 'no_field_focus', 'confidence' => 0.7];
            }
        }

        // Paste detection
        if (!empty($form['pasteDetected']) && (float) ($form['fieldsWithPaste'] ?? 0) > 2) {
            $checks++;
            $score += 0.4;
            $detections[] = ['category' => 'form', 'signal' => 'multiple_pastes', 'confidence' => 0.4];
        }

        return $checks > 0 ? min(1.0, $score / $checks) : 0.0;
    }

    /**
     * Basic timezone/language mismatch detection
     */
    private function detect_locale_mismatch(string $timezone, string $language): bool
    {
        // Very basic check - could be expanded
        $tz_lower = strtolower($timezone);
        $lang = strtolower(substr($language, 0, 2));

        $tz_lang_map = [
            'asia/tokyo' => ['ja'],
            'asia/shanghai' => ['zh'],
            'asia/seoul' => ['ko'],
            'europe/paris' => ['fr'],
            'europe/berlin' => ['de'],
            'europe/madrid' => ['es'],
            'america/sao_paulo' => ['pt'],
        ];

        if (isset($tz_lang_map[$tz_lower])) {
            return !in_array($lang, $tz_lang_map[$tz_lower]);
        }

        return false;
    }
}
