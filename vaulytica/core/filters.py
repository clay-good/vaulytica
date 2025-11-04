"""Advanced filtering for scan results."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Callable, Any
from enum import Enum

import structlog

logger = structlog.get_logger(__name__)


class FilterOperator(Enum):
    """Filter operators."""

    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUAL = "lte"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    IN = "in"
    NOT_IN = "not_in"
    REGEX = "regex"


@dataclass
class Filter:
    """A single filter condition."""

    field: str
    operator: FilterOperator
    value: Any

    def matches(self, obj: Any) -> bool:
        """Check if object matches this filter.

        Args:
            obj: Object to check

        Returns:
            True if object matches filter
        """
        # Get field value from object
        field_value = self._get_field_value(obj, self.field)

        if field_value is None:
            return False

        # Apply operator
        if self.operator == FilterOperator.EQUALS:
            return field_value == self.value

        elif self.operator == FilterOperator.NOT_EQUALS:
            return field_value != self.value

        elif self.operator == FilterOperator.GREATER_THAN:
            return field_value > self.value

        elif self.operator == FilterOperator.GREATER_THAN_OR_EQUAL:
            return field_value >= self.value

        elif self.operator == FilterOperator.LESS_THAN:
            return field_value < self.value

        elif self.operator == FilterOperator.LESS_THAN_OR_EQUAL:
            return field_value <= self.value

        elif self.operator == FilterOperator.CONTAINS:
            return self.value in str(field_value)

        elif self.operator == FilterOperator.NOT_CONTAINS:
            return self.value not in str(field_value)

        elif self.operator == FilterOperator.STARTS_WITH:
            return str(field_value).startswith(str(self.value))

        elif self.operator == FilterOperator.ENDS_WITH:
            return str(field_value).endswith(str(self.value))

        elif self.operator == FilterOperator.IN:
            return field_value in self.value

        elif self.operator == FilterOperator.NOT_IN:
            return field_value not in self.value

        elif self.operator == FilterOperator.REGEX:
            import re

            return bool(re.search(str(self.value), str(field_value)))

        return False

    def _get_field_value(self, obj: Any, field: str) -> Any:
        """Get field value from object.

        Args:
            obj: Object
            field: Field name (supports dot notation)

        Returns:
            Field value or None
        """
        # Support dot notation for nested fields
        parts = field.split(".")
        value = obj

        for part in parts:
            if hasattr(value, part):
                value = getattr(value, part)
            elif isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return None

        return value


@dataclass
class FilterGroup:
    """Group of filters with AND/OR logic."""

    filters: List[Filter]
    operator: str = "AND"  # AND or OR

    def matches(self, obj: Any) -> bool:
        """Check if object matches this filter group.

        Args:
            obj: Object to check

        Returns:
            True if object matches filter group
        """
        if not self.filters:
            return True

        if self.operator == "AND":
            return all(f.matches(obj) for f in self.filters)
        else:  # OR
            return any(f.matches(obj) for f in self.filters)


class FilterBuilder:
    """Builder for creating complex filters."""

    def __init__(self):
        """Initialize filter builder."""
        self.filters: List[Filter] = []

    def add(self, field: str, operator: FilterOperator, value: Any) -> "FilterBuilder":
        """Add a filter.

        Args:
            field: Field name
            operator: Filter operator
            value: Filter value

        Returns:
            Self for chaining
        """
        self.filters.append(Filter(field, operator, value))
        return self

    def equals(self, field: str, value: Any) -> "FilterBuilder":
        """Add equals filter."""
        return self.add(field, FilterOperator.EQUALS, value)

    def not_equals(self, field: str, value: Any) -> "FilterBuilder":
        """Add not equals filter."""
        return self.add(field, FilterOperator.NOT_EQUALS, value)

    def greater_than(self, field: str, value: Any) -> "FilterBuilder":
        """Add greater than filter."""
        return self.add(field, FilterOperator.GREATER_THAN, value)

    def less_than(self, field: str, value: Any) -> "FilterBuilder":
        """Add less than filter."""
        return self.add(field, FilterOperator.LESS_THAN, value)

    def contains(self, field: str, value: str) -> "FilterBuilder":
        """Add contains filter."""
        return self.add(field, FilterOperator.CONTAINS, value)

    def in_list(self, field: str, values: List[Any]) -> "FilterBuilder":
        """Add in list filter."""
        return self.add(field, FilterOperator.IN, values)

    def regex(self, field: str, pattern: str) -> "FilterBuilder":
        """Add regex filter."""
        return self.add(field, FilterOperator.REGEX, pattern)

    def build(self, operator: str = "AND") -> FilterGroup:
        """Build filter group.

        Args:
            operator: AND or OR

        Returns:
            FilterGroup
        """
        return FilterGroup(filters=self.filters, operator=operator)


class ResultFilter:
    """Filter for scan results with common presets."""

    @staticmethod
    def by_risk_score(min_score: int, max_score: int = 100) -> FilterGroup:
        """Filter by risk score range.

        Args:
            min_score: Minimum risk score
            max_score: Maximum risk score

        Returns:
            FilterGroup
        """
        return FilterBuilder().greater_than_or_equal("risk_score", min_score).less_than_or_equal(
            "risk_score", max_score
        ).build()

    @staticmethod
    def by_user(user_emails: List[str]) -> FilterGroup:
        """Filter by user email.

        Args:
            user_emails: List of user emails

        Returns:
            FilterGroup
        """
        return FilterBuilder().in_list("owner_email", user_emails).build()

    @staticmethod
    def by_date_range(start_date: datetime, end_date: Optional[datetime] = None) -> FilterGroup:
        """Filter by date range.

        Args:
            start_date: Start date
            end_date: End date (default: now)

        Returns:
            FilterGroup
        """
        if end_date is None:
            end_date = datetime.now(timezone.utc)

        return (
            FilterBuilder()
            .greater_than_or_equal("modified_time", start_date)
            .less_than_or_equal("modified_time", end_date)
            .build()
        )

    @staticmethod
    def by_file_type(mime_types: List[str]) -> FilterGroup:
        """Filter by file MIME type.

        Args:
            mime_types: List of MIME types

        Returns:
            FilterGroup
        """
        return FilterBuilder().in_list("mime_type", mime_types).build()

    @staticmethod
    def external_only() -> FilterGroup:
        """Filter for externally shared files only.

        Returns:
            FilterGroup
        """
        return FilterBuilder().equals("is_external", True).build()

    @staticmethod
    def public_only() -> FilterGroup:
        """Filter for publicly shared files only.

        Returns:
            FilterGroup
        """
        return FilterBuilder().equals("is_public", True).build()

    @staticmethod
    def with_pii() -> FilterGroup:
        """Filter for files with PII.

        Returns:
            FilterGroup
        """
        return FilterBuilder().equals("has_pii", True).build()

    @staticmethod
    def high_risk() -> FilterGroup:
        """Filter for high risk files (score >= 75).

        Returns:
            FilterGroup
        """
        return ResultFilter.by_risk_score(75, 100)

    @staticmethod
    def medium_risk() -> FilterGroup:
        """Filter for medium risk files (score 50-74).

        Returns:
            FilterGroup
        """
        return ResultFilter.by_risk_score(50, 74)

    @staticmethod
    def low_risk() -> FilterGroup:
        """Filter for low risk files (score 25-49).

        Returns:
            FilterGroup
        """
        return ResultFilter.by_risk_score(25, 49)


def apply_filters(items: List[Any], filter_group: FilterGroup) -> List[Any]:
    """Apply filters to a list of items.

    Args:
        items: List of items to filter
        filter_group: Filter group to apply

    Returns:
        Filtered list
    """
    return [item for item in items if filter_group.matches(item)]


def sort_results(
    items: List[Any],
    sort_by: str,
    reverse: bool = False,
) -> List[Any]:
    """Sort results by a field.

    Args:
        items: List of items to sort
        sort_by: Field name to sort by
        reverse: Sort in reverse order

    Returns:
        Sorted list
    """

    def get_sort_key(item: Any) -> Any:
        """Get sort key from item."""
        if hasattr(item, sort_by):
            return getattr(item, sort_by)
        elif isinstance(item, dict) and sort_by in item:
            return item[sort_by]
        return None

    return sorted(items, key=get_sort_key, reverse=reverse)

