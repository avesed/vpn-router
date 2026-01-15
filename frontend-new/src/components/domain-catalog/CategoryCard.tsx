import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from "../ui/card";
import { Button } from "../ui/button";
import { Badge } from "../ui/badge";
import { Plus, ChevronDown } from "lucide-react";

interface CategoryCardProps {
  id: string;
  name: string;
  description?: string;
  count?: number;
  tags?: string[];
  lists?: any[];
  actionLabel: string;
  onAdd: () => void;
}

export function CategoryCard({ name, description, count, tags, lists, actionLabel, onAdd }: CategoryCardProps) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);

  return (
    <Card className="flex flex-col h-full">
      <CardHeader className="pb-2">
        <div className="flex justify-between items-start">
          <CardTitle className="text-lg">{name}</CardTitle>
          {count !== undefined && (
            <Badge variant="secondary" className="ml-2">
              {t("catalog.ruleCount", { count })}
            </Badge>
          )}
        </div>
        {description && <CardDescription className="line-clamp-2">{description}</CardDescription>}
      </CardHeader>
      <CardContent className="flex-grow">
        <div className="flex flex-wrap gap-1 mt-2">
          {tags?.map((tag) => (
            <Badge key={tag} variant="outline" className="text-xs">
              {tag}
            </Badge>
          ))}
        </div>
        
        {lists && lists.length > 0 && (
          <div className="mt-4">
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={() => setExpanded(!expanded)} 
              className="w-full justify-between px-0 hover:bg-transparent"
            >
              <span className="text-sm font-medium">
                {t("catalog.subLists", { count: lists.length })}
              </span>
              <ChevronDown className={`h-4 w-4 transition-transform ${expanded ? "rotate-180" : ""}`} />
            </Button>
            {expanded && (
               <div className="mt-2 space-y-2 max-h-40 overflow-y-auto pr-2">
                 {lists.map(list => (
                   <div key={list.id} className="text-xs flex justify-between items-center p-1 rounded hover:bg-muted">
                     <span className="font-mono truncate max-w-[150px]" title={list.id}>{list.id}</span>
                     <span className="text-muted-foreground">{list.domain_count}</span>
                   </div>
                 ))}
               </div>
            )}
          </div>
        )}
      </CardContent>
      <CardFooter>
        <Button onClick={onAdd} className="w-full" size="sm">
          <Plus className="w-4 h-4 mr-2" />
          {actionLabel}
        </Button>
      </CardFooter>
    </Card>
  );
}
