defmodule ZentinelCp.Analytics.Workers.WafAuditWorker do
  @moduledoc """
  Oban worker for asynchronous AI auditing of WAF events.
  """
  use Oban.Worker, queue: :security, max_attempts: 3

  alias ZentinelCp.Repo
  alias ZentinelCp.Analytics.WafEvent
  alias ZentinelCp.Ai.AuditorClient
  require Logger

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"event_id" => event_id}}) do
    case Repo.get(WafEvent, event_id) do
      nil -> 
        :ok
      
      event ->
        # Perform deep audit for second opinion
        case AuditorClient.audit(event.matched_data, event.id) do
          {:ok, result} ->
            # Update event with AI results
            event_changes = %{
              ai_score: result.confidence,
              ai_recommendation: if(result.is_attack, do: "block", else: "allow"),
              ai_metadata: %{
                audited_at: DateTime.utc_now(),
                reason: result.reason,
                auditor: "zentinel-agent-ai-auditor-rust"
              }
            }

            # CROSS-VALIDATION: Only learn if BOTH agree and AI confidence is high
            if event.rule_type == "zentinelsec" and result.is_attack and result.confidence > 0.8 do
              Logger.info("WafAuditWorker: Verified detection (ModSec + AI). Learning pattern.")
              ZentinelCp.Waf.learn_from_event(event.project_id, event)
            end

            event
            |> WafEvent.changeset(event_changes)
            |> Repo.update()

          {:error, reason} ->
            Logger.error("WafAuditWorker failed: #{inspect(reason)}")
            {:error, reason}
        end
        end
    end
  end
end
