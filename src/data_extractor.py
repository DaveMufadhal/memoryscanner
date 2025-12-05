"""
Data Extraction Layer - Defensive Programming for Volatility Output

This module provides a centralized, type-safe way to extract data from Volatility plugin outputs.
It handles multiple data formats and ensures consistent data structure throughout the analysis pipeline.

Design Principles:
1. Never trust data types - always validate
2. Fail gracefully - return empty structures instead of crashing
3. Log warnings for unexpected formats
4. Provide consistent interfaces

Author: MemoryScanner Team
Date: December 2, 2025
"""

from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger("forensic_analyzer")


class DataExtractor:
    """
    Centralized data extraction with type safety and error handling.
    
    This class ensures that regardless of how Volatility returns data
    (list, dict, wrapped dict, error dict), we always get a consistent
    list of dictionaries for processing.
    """
    
    @staticmethod
    def extract_plugin_data(
        raw_outputs: Dict[str, Any],
        plugin_name: str,
        required_fields: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Extract data from plugin output with comprehensive error handling.
        
        Args:
            raw_outputs: Dictionary of all plugin outputs
            plugin_name: Name of the plugin to extract data from
            required_fields: Optional list of fields that must be present
        
        Returns:
            List of dictionaries representing plugin data rows
            Returns empty list if plugin failed or data is invalid
        
        Examples:
            >>> data = DataExtractor.extract_plugin_data(outputs, "windows.pslist.PsList")
            >>> processes = data  # Always a list of dicts
        """
        # Plugin not in outputs
        if plugin_name not in raw_outputs:
            logger.warning(f"Plugin {plugin_name} not found in outputs")
            return []
        
        result = raw_outputs[plugin_name]
        
        # Case 1: Plugin failed (error dict)
        if isinstance(result, dict) and 'error' in result:
            logger.warning(f"Plugin {plugin_name} failed: {result.get('error', 'Unknown error')}")
            return []
        
        # Case 2: Wrapped structure with 'data' key (our new format)
        if isinstance(result, dict) and 'data' in result:
            data = result['data']
            if isinstance(data, list):
                return DataExtractor._validate_list_data(data, plugin_name, required_fields)
            else:
                logger.warning(f"Plugin {plugin_name} 'data' field is not a list: {type(data)}")
                return []
        
        # Case 3: Direct list (old format or manual parsing)
        if isinstance(result, list):
            return DataExtractor._validate_list_data(result, plugin_name, required_fields)
        
        # Case 4: Single dict (wrap in list)
        if isinstance(result, dict):
            logger.info(f"Plugin {plugin_name} returned single dict, wrapping in list")
            return [result]
        
        # Case 5: Unexpected format
        logger.error(f"Plugin {plugin_name} returned unexpected type: {type(result)}")
        return []
    
    @staticmethod
    def _validate_list_data(
        data: List[Any],
        plugin_name: str,
        required_fields: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Validate that list contains dictionaries with required fields.
        
        Returns:
            Filtered list containing only valid dict entries
        """
        if not data:
            logger.debug(f"Plugin {plugin_name} returned empty list")
            return []
        
        valid_items = []
        invalid_count = 0
        
        for item in data:
            # Skip non-dict items
            if not isinstance(item, dict):
                invalid_count += 1
                continue
            
            # Check required fields if specified
            if required_fields:
                missing_fields = [f for f in required_fields if f not in item]
                if missing_fields:
                    logger.debug(f"Item missing required fields {missing_fields}: {item}")
                    invalid_count += 1
                    continue
            
            valid_items.append(item)
        
        if invalid_count > 0:
            logger.warning(f"Plugin {plugin_name}: Filtered out {invalid_count} invalid items")
        
        logger.debug(f"Plugin {plugin_name}: Extracted {len(valid_items)} valid items")
        return valid_items
    
    @staticmethod
    def safe_get(item: Any, key: str, default: Any = None) -> Any:
        """
        Safely get value from dict-like object.
        
        Args:
            item: Object to get value from
            key: Key to retrieve
            default: Default value if key not found or item is not a dict
        
        Returns:
            Value from dict or default
        """
        if isinstance(item, dict):
            return item.get(key, default)
        return default
    
    @staticmethod
    def extract_field(
        items: List[Dict[str, Any]],
        field: str,
        default: Any = None,
        unique: bool = False
    ) -> List[Any]:
        """
        Extract a specific field from all items in a list.
        
        Args:
            items: List of dictionaries
            field: Field name to extract
            default: Default value if field not found
            unique: If True, return only unique values
        
        Returns:
            List of field values
        """
        values = [DataExtractor.safe_get(item, field, default) for item in items]
        
        if unique:
            return list(set(values))
        
        return values
    
    @staticmethod
    def filter_items(
        items: List[Dict[str, Any]],
        conditions: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Filter items based on field conditions.
        
        Args:
            items: List of dictionaries to filter
            conditions: Dict of {field: value} conditions (all must match)
        
        Returns:
            Filtered list
        
        Example:
            >>> filtered = DataExtractor.filter_items(processes, {"ImageFileName": "cmd.exe"})
        """
        filtered = []
        
        for item in items:
            if not isinstance(item, dict):
                continue
            
            match = True
            for field, expected_value in conditions.items():
                actual_value = item.get(field)
                if actual_value != expected_value:
                    match = False
                    break
            
            if match:
                filtered.append(item)
        
        return filtered
    
    @staticmethod
    def get_statistics(items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get statistics about extracted data.
        
        Returns:
            Dict with count, field names, sample item
        """
        if not items:
            return {"count": 0, "fields": [], "sample": None}
        
        first_item = items[0] if isinstance(items[0], dict) else {}
        
        return {
            "count": len(items),
            "fields": list(first_item.keys()),
            "sample": first_item
        }


# Convenience function for backward compatibility
def extract_plugin_data(raw_outputs: Dict[str, Any], plugin_name: str) -> List[Dict[str, Any]]:
    """
    Backward-compatible function for extracting plugin data.
    """
    return DataExtractor.extract_plugin_data(raw_outputs, plugin_name)
