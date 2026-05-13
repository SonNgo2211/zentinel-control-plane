defmodule ZentinelCp.Repo.Migrations.AddAiKnowledgeToWafPolicies do
  use Ecto.Migration

  def change do
    alter table(:waf_policies) do
      add :ai_knowledge, :map, default: %{}
    end
  end
end
