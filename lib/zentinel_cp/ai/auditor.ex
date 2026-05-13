defmodule ZentinelCp.Ai.Auditor do
  @moduledoc """
  AI Security Auditor for evaluating WAF events at scale.

  Provides clustering logic to group similar events and scoring algorithms
  to distinguish between True Positives and False Positives.
  """

  alias ZentinelCp.Analytics.WafEvent

  @doc """
  Clusters a list of WAF events by their fingerprint.
  Returns a map of fingerprint => [events].
  """
  def cluster_events(events) when is_list(events) do
    Enum.group_by(events, &generate_fingerprint/1)
  end

  @doc """
  Generates a unique fingerprint for a WAF event.
  Normalizes path and matched_data to ensure similar requests cluster together.
  """
  def generate_fingerprint(%WafEvent{} = event) do
    # Normalize path (remove UUIDs/IDs)
    path = Regex.replace(~r/\/[0-9a-f-]{36}/, event.path || "", "/:id")
    path = Regex.replace(~r/\/\d+/, path, "/:num")

    # Normalize matched data (first 32 chars)
    data = String.slice(event.matched_data || "", 0, 32)
    
    :crypto.hash(:sha256, "#{event.rule_id}|#{event.method}|#{path}|#{data}")
    |> Base.encode16()
  end

  @doc """
  Scores a WAF event (or a representative sample from a cluster).
  Returns a float between 0.0 (Clean) and 1.0 (Attack).
  """
  def score_event(%WafEvent{} = event) do
    data = event.matched_data || ""
    
    # 1. Entropy Score (High entropy often means obfuscation)
    entropy = calculate_entropy(data)
    entropy_score = min(entropy / 8.0, 1.0) # 8.0 is max entropy for byte-level

    # 2. Token Analysis (Heuristics)
    token_score = calculate_token_score(data, event.rule_id)

    # 3. Confidence Factor (Weighted average)
    (entropy_score * 0.4 + token_score * 0.6)
    |> Float.round(4)
  end

  @doc """
  Calculates the Shannon entropy of a string.
  """
  def calculate_entropy(""), do: 0.0
  def calculate_entropy(data) do
    len = String.length(data)
    frequencies = 
      data
      |> String.to_charlist()
      |> Enum.frequencies()
    
    Enum.reduce(frequencies, 0.0, fn {_, count}, acc ->
      p = count / len
      acc - (p * :math.log2(p))
    end)
  end

  defp calculate_token_score(data, rule_id) do
    data = String.downcase(data)
    
    cond do
      # SQLi checks
      String.contains?(rule_id, "942") ->
        if String.contains?(data, ["select", "union", "insert", "update", "delete", "from", "--", "/*"]) do
          0.9
        else
          0.3
        end

      # XSS checks
      String.contains?(rule_id, "941") ->
        if String.contains?(data, ["<script", "javascript:", "onclick", "onerror", "alert("]) do
          0.95
        else
          0.4
        end

      # Default fallback
      true ->
        0.5
    end
  end

  @doc """
  Provides a recommended action based on the score.
  """
  def recommend_action(score) do
    cond do
      score > 0.8 -> :confirm_attack
      score < 0.2 -> :likely_false_positive
      true -> :needs_manual_review
    end
  end
end
