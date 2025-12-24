import { cn } from "@/lib/utils";
import { getCategoryColor } from "@/lib/utils/validators";

interface CategoryBadgeProps {
  category: string;
  className?: string;
}

export function CategoryBadge({ category, className }: CategoryBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 text-xs font-medium rounded border capitalize",
        getCategoryColor(category),
        className
      )}
    >
      {category}
    </span>
  );
}
