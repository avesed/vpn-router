import { useTranslation } from "react-i18next";
import { EgressTabs } from "../components/egress/EgressTabs";

export default function EgressPage() {
  const { t } = useTranslation();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t("egress.title")}</h1>
        <p className="text-muted-foreground">
          {t("egress.subtitle")}
        </p>
      </div>
      <EgressTabs />
    </div>
  );
}
