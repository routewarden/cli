package engine

import (
	"regexp"
	"strings"
)

// AIBotProfile represents the bot filtering strategy profile.
type AIBotProfile string

const (
	AIBotProfileAll        = "all"
	AIBotProfileTrainOnly  = "train_only"
	AIBotProfileAggressive = "aggressive"
	AIBotProfileCustom     = "custom"
)

var (
	// Training/Harvester crawlers (Tier 1): Mass scrape content for LLM pre-training.
	reAITrainingBots = regexp.MustCompile(`(?i)(GPTBot|ClaudeBot|anthropic-ai|Claude-Web|Google-Extended|Bytespider|CCBot|Applebot-Extended|cohere-ai|Diffbot|ImagesiftBot|FacebookBot|Meta-ExternalAgent|Meta-ExternalFetcher|Omgilibot|Timpibot|Webzio|YouBot)`)

	// Search and real-time conversational agents (Tier 2): Retrieve live pages to answer user prompts and cite sources.
	reAISearchBots = regexp.MustCompile(`(?i)(OAI-SearchBot|ChatGPT-User|PerplexityBot)`)

	// Aggressive bots known to disregard crawl delays, robots.txt, or hammer infrastructure.
	reAIAggressiveBots = regexp.MustCompile(`(?i)(Bytespider|ClaudeBot|CCBot|Diffbot)`)
)

// MatchAIBot evaluates a User-Agent against the chosen profile.
// It returns true and the matched category name if the bot matches the blocking rule.
func MatchAIBot(userAgent string, profile string) (bool, string) {
	ua := strings.TrimSpace(userAgent)
	if ua == "" {
		return false, ""
	}

	normProfile := strings.ToLower(strings.TrimSpace(profile))
	if normProfile == "" {
		normProfile = AIBotProfileTrainOnly
	}

	switch normProfile {
	case AIBotProfileAll:
		if reAITrainingBots.MatchString(ua) {
			return true, "ai_training_bot"
		}
		if reAISearchBots.MatchString(ua) {
			return true, "ai_search_bot"
		}
		if reAIAggressiveBots.MatchString(ua) {
			return true, "ai_aggressive_bot"
		}
	case AIBotProfileAggressive:
		if reAIAggressiveBots.MatchString(ua) {
			return true, "ai_aggressive_bot"
		}
	case AIBotProfileTrainOnly:
		if reAITrainingBots.MatchString(ua) {
			return true, "ai_training_bot"
		}
	case AIBotProfileCustom:
		// Custom profile does not block built-in registries; relies exclusively on BlockUserAgents.
		return false, ""
	default:
		// Default to train_only if invalid profile provided
		if reAITrainingBots.MatchString(ua) {
			return true, "ai_training_bot"
		}
	}

	return false, ""
}
