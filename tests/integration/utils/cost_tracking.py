# Cost Tracking Utilities for GSAi API Testing Framework
import time
import json
from typing import Dict, Any, List
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class RequestCost:
    """Track cost for individual request"""
    timestamp: float
    endpoint: str
    method: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    estimated_cost: float
    model: str = ""
    test_id: str = ""


class CostTracker:
    """Enhanced cost tracking with detailed analytics"""
    
    def __init__(self, budget_limit: float = 50.0):
        self.budget_limit = budget_limit
        self.requests: List[RequestCost] = []
        self.daily_costs: Dict[str, float] = {}
        self.model_costs: Dict[str, float] = {}
        self.endpoint_costs: Dict[str, float] = {}
        
    def add_request(self, endpoint: str, method: str, input_tokens: int, 
                   output_tokens: int = 0, model: str = "", test_id: str = "",
                   cost_per_1k_tokens: float = 0.01):
        """Add a request to cost tracking"""
        total_tokens = input_tokens + output_tokens
        estimated_cost = (total_tokens / 1000) * cost_per_1k_tokens
        
        request_cost = RequestCost(
            timestamp=time.time(),
            endpoint=endpoint,
            method=method,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            estimated_cost=estimated_cost,
            model=model,
            test_id=test_id
        )
        
        self.requests.append(request_cost)
        
        # Update daily costs
        date_key = time.strftime("%Y-%m-%d")
        self.daily_costs[date_key] = self.daily_costs.get(date_key, 0) + estimated_cost
        
        # Update model costs
        if model:
            self.model_costs[model] = self.model_costs.get(model, 0) + estimated_cost
        
        # Update endpoint costs
        self.endpoint_costs[endpoint] = self.endpoint_costs.get(endpoint, 0) + estimated_cost
        
        # Check budget limit
        if self.get_total_cost() > self.budget_limit:
            logger.warning(f"Budget limit exceeded: ${self.get_total_cost():.2f} > ${self.budget_limit}")
            return False
        
        return True
    
    def get_total_cost(self) -> float:
        """Get total cost across all requests"""
        return sum(req.estimated_cost for req in self.requests)
    
    def get_total_tokens(self) -> int:
        """Get total tokens across all requests"""
        return sum(req.total_tokens for req in self.requests)
    
    def get_request_count(self) -> int:
        """Get total request count"""
        return len(self.requests)
    
    def get_daily_cost(self, date: str = None) -> float:
        """Get cost for specific date (default: today)"""
        if date is None:
            date = time.strftime("%Y-%m-%d")
        return self.daily_costs.get(date, 0.0)
    
    def get_model_breakdown(self) -> Dict[str, Dict[str, Any]]:
        """Get cost breakdown by model"""
        breakdown = {}
        
        for model, cost in self.model_costs.items():
            model_requests = [req for req in self.requests if req.model == model]
            breakdown[model] = {
                "total_cost": cost,
                "request_count": len(model_requests),
                "total_tokens": sum(req.total_tokens for req in model_requests),
                "avg_cost_per_request": cost / len(model_requests) if model_requests else 0
            }
        
        return breakdown
    
    def get_endpoint_breakdown(self) -> Dict[str, Dict[str, Any]]:
        """Get cost breakdown by endpoint"""
        breakdown = {}
        
        for endpoint, cost in self.endpoint_costs.items():
            endpoint_requests = [req for req in self.requests if req.endpoint == endpoint]
            breakdown[endpoint] = {
                "total_cost": cost,
                "request_count": len(endpoint_requests),
                "total_tokens": sum(req.total_tokens for req in endpoint_requests),
                "avg_cost_per_request": cost / len(endpoint_requests) if endpoint_requests else 0
            }
        
        return breakdown
    
    def get_cost_trends(self) -> Dict[str, List[float]]:
        """Get cost trends over time"""
        trends = {}
        
        # Group by hour
        hourly_costs = {}
        for req in self.requests:
            hour_key = time.strftime("%Y-%m-%d %H:00", time.localtime(req.timestamp))
            hourly_costs[hour_key] = hourly_costs.get(hour_key, 0) + req.estimated_cost
        
        trends["hourly"] = list(hourly_costs.values())
        trends["timestamps"] = list(hourly_costs.keys())
        
        return trends
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive cost summary"""
        return {
            "total_cost": self.get_total_cost(),
            "total_tokens": self.get_total_tokens(),
            "request_count": self.get_request_count(),
            "avg_cost_per_request": self.get_total_cost() / max(1, self.get_request_count()),
            "avg_tokens_per_request": self.get_total_tokens() / max(1, self.get_request_count()),
            "budget_limit": self.budget_limit,
            "budget_remaining": max(0, self.budget_limit - self.get_total_cost()),
            "budget_utilization": (self.get_total_cost() / self.budget_limit) * 100,
            "daily_costs": self.daily_costs,
            "model_breakdown": self.get_model_breakdown(),
            "endpoint_breakdown": self.get_endpoint_breakdown()
        }
    
    def export_to_file(self, filepath: Path) -> None:
        """Export cost data to JSON file"""
        data = {
            "summary": self.get_summary(),
            "requests": [asdict(req) for req in self.requests],
            "export_timestamp": time.time()
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Cost data exported to {filepath}")
    
    def load_from_file(self, filepath: Path) -> None:
        """Load cost data from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # Restore requests
        self.requests = [RequestCost(**req) for req in data["requests"]]
        
        # Rebuild aggregations
        self._rebuild_aggregations()
        
        logger.info(f"Cost data loaded from {filepath}")
    
    def _rebuild_aggregations(self) -> None:
        """Rebuild aggregated cost data from requests"""
        self.daily_costs = {}
        self.model_costs = {}
        self.endpoint_costs = {}
        
        for req in self.requests:
            # Daily costs
            date_key = time.strftime("%Y-%m-%d", time.localtime(req.timestamp))
            self.daily_costs[date_key] = self.daily_costs.get(date_key, 0) + req.estimated_cost
            
            # Model costs
            if req.model:
                self.model_costs[req.model] = self.model_costs.get(req.model, 0) + req.estimated_cost
            
            # Endpoint costs
            self.endpoint_costs[req.endpoint] = self.endpoint_costs.get(req.endpoint, 0) + req.estimated_cost
    
    def reset(self) -> None:
        """Reset all cost tracking data"""
        self.requests = []
        self.daily_costs = {}
        self.model_costs = {}
        self.endpoint_costs = {}
        
        logger.info("Cost tracking data reset")
    
    def is_over_budget(self) -> bool:
        """Check if over budget"""
        return self.get_total_cost() > self.budget_limit
    
    def get_budget_warning_threshold(self, threshold: float = 0.8) -> bool:
        """Check if approaching budget limit"""
        return self.get_total_cost() > (self.budget_limit * threshold)


def estimate_tokens(text: str) -> int:
    """Rough estimation of tokens in text"""
    # Very rough estimation: ~4 characters per token
    return len(text) // 4


def estimate_request_cost(request_data: Dict[str, Any], 
                         cost_per_1k_tokens: float = 0.01) -> float:
    """Estimate cost for a request"""
    estimated_tokens = 50  # Default
    
    if "messages" in request_data:
        # Chat completion request
        estimated_tokens = sum(
            estimate_tokens(msg.get("content", ""))
            for msg in request_data["messages"]
            if isinstance(msg.get("content"), str)
        )
    elif "input" in request_data:
        # Embedding request
        estimated_tokens = estimate_tokens(str(request_data["input"]))
    
    # Add output tokens estimate
    max_tokens = request_data.get("max_tokens", 50)
    estimated_tokens += max_tokens
    
    return (estimated_tokens / 1000) * cost_per_1k_tokens