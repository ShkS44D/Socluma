from __future__ import annotations
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
import yaml

from src.models.sqlalchemy import DetectionRule, RuleType
from src.models.pydantic import DetectionRuleCreate, DetectionRuleUpdate
from src.services.sigma_rule_service import sigma_rule_service


class DetectionRuleService:
    def list_rules(
        self, 
        db: Session, 
        tenant_id: str,
        enabled_only: Optional[bool] = None
    ) -> list[DetectionRule]:
        query = db.query(DetectionRule).filter(DetectionRule.tenant_id == tenant_id)
        
        if enabled_only is not None:
            query = query.filter(DetectionRule.enabled == enabled_only)
            
        return query.order_by(DetectionRule.created_at.desc()).all()

    def get_rule_by_id(self, db: Session, tenant_id: str, rule_id: str) -> DetectionRule:
        rule = db.query(DetectionRule).filter(
            DetectionRule.id == rule_id, DetectionRule.tenant_id == tenant_id
        ).first()
        if not rule:
            raise ValueError("Detection rule not found")
        return rule

    def create_rule(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        rule_data: DetectionRuleCreate,
    ) -> DetectionRule:
        # Determine rule_type from either rule_type or type fields
        rule_type = rule_data.rule_type if rule_data.rule_type is not None else rule_data.type
        
        # Initialize fields
        sigma_rule = rule_data.sigma_rule or ""
        query = rule_data.query or ""
        condition = rule_data.condition
        rule_content = rule_data.rule_content
        
        # Handle Sigma content conversion if provided
        if rule_type == RuleType.SIGMA and not rule_content and sigma_rule:
            validation = sigma_rule_service.validate(sigma_rule)
            if not validation.valid:
                raise ValueError("; ".join(validation.errors))
            rule_content = validation.normalized

        if rule_type == RuleType.SIGMA and rule_content:
            validation = sigma_rule_service.validate(rule_content)
            if not validation.valid:
                raise ValueError("; ".join(validation.errors))
            rule_content = validation.normalized
            sigma_rule = sigma_rule_service.export_yaml(rule_content)
            if not rule_data.event_type:
                inferred_event_type = sigma_rule_service.infer_event_type(rule_content)
            else:
                inferred_event_type = rule_data.event_type
            severity = rule_data.severity or sigma_rule_service.infer_severity(rule_content)
        else:
            inferred_event_type = rule_data.event_type
            severity = rule_data.severity

        # Preserve legacy custom condition generation for rule_content.
        if rule_content and rule_type != RuleType.SIGMA:
            # Convert rule_content to YAML for sigma_rule
            sigma_rule = yaml.safe_dump(rule_content, sort_keys=False)
            
            # Try to generate a simple query/condition from Sigma selection
            if 'detection' in rule_content:
                detection = rule_content['detection']
                if 'selection' in detection:
                    selection = detection['selection']
                    if isinstance(selection, dict):
                        # Generate a simple condition dictionary
                        condition = selection
                        # Generate a simple query string like "key=value"
                        query_parts = [f"{k}={v}" for k, v in selection.items()]
                        query = " ".join(query_parts)
        
        rule = DetectionRule(
            tenant_id=tenant_id,
            name=rule_data.name,
            description=rule_data.description,
            # Set both type and rule_type for backward compatibility
            type=rule_type,
            rule_type=rule_type,
            query=query,
            sigma_rule=sigma_rule,
            rule_content=rule_content,  # Store the original rule_content
            event_type=inferred_event_type,
            severity=severity,
            enabled=rule_data.enabled,
            condition=condition,
            mitre_technique_id=rule_data.mitre_technique_id,
            created_by=user_id,
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        return rule

    def update_rule(
        self,
        db: Session,
        tenant_id: str,
        rule_id: str,
        update_data: DetectionRuleUpdate,
    ) -> DetectionRule:
        rule = self.get_rule_by_id(db, tenant_id, rule_id)
        
        update_dict = update_data.model_dump(exclude_unset=True)
        
        # Handle rule_type/type compatibility
        if 'rule_type' in update_dict:
            rule.rule_type = update_dict['rule_type']
            rule.type = update_dict['rule_type']
        elif 'type' in update_dict:
            rule.type = update_dict['type']
            rule.rule_type = update_dict['type']
            
        # Handle rule_content conversion if provided in update
        if 'sigma_rule' in update_dict and update_dict.get('sigma_rule') and (rule.rule_type == RuleType.SIGMA or update_dict.get('rule_type') == RuleType.SIGMA or update_dict.get('type') == RuleType.SIGMA):
            validation = sigma_rule_service.validate(update_dict['sigma_rule'])
            if not validation.valid:
                raise ValueError("; ".join(validation.errors))
            update_dict['rule_content'] = validation.normalized

        if 'rule_content' in update_dict and update_dict['rule_content']:
            rule_content = update_dict['rule_content']
            if rule.rule_type == RuleType.SIGMA or update_dict.get('rule_type') == RuleType.SIGMA or update_dict.get('type') == RuleType.SIGMA:
                validation = sigma_rule_service.validate(rule_content)
                if not validation.valid:
                    raise ValueError("; ".join(validation.errors))
                rule_content = validation.normalized
                rule.rule_content = rule_content
                rule.sigma_rule = sigma_rule_service.export_yaml(rule_content)
                if 'event_type' not in update_dict:
                    rule.event_type = sigma_rule_service.infer_event_type(rule_content)
                if 'severity' not in update_dict:
                    rule.severity = sigma_rule_service.infer_severity(rule_content)
            else:
                rule.rule_content = rule_content
                # Convert rule_content to YAML for sigma_rule
                rule.sigma_rule = yaml.safe_dump(rule_content, sort_keys=False)
            
            # Try to generate condition/query from Sigma selection
            if rule.rule_type != RuleType.SIGMA and 'detection' in rule_content:
                detection = rule_content['detection']
                if 'selection' in detection:
                    selection = detection['selection']
                    if isinstance(selection, dict):
                        rule.condition = selection
                        query_parts = [f"{k}={v}" for k, v in selection.items()]
                        rule.query = " ".join(query_parts)
        
        # Update other fields (excluding those we handled above)
        for key, value in update_dict.items():
            if key not in ('rule_type', 'type', 'rule_content'):
                setattr(rule, key, value)
            
        db.add(rule)
        db.commit()
        db.refresh(rule)
        return rule

    def toggle_rule(
        self,
        db: Session,
        tenant_id: str,
        rule_id: str,
    ) -> DetectionRule:
        rule = self.get_rule_by_id(db, tenant_id, rule_id)
        rule.enabled = not rule.enabled
        db.add(rule)
        db.commit()
        db.refresh(rule)
        return rule

    def delete_rule(self, db: Session, tenant_id: str, rule_id: str) -> None:
        rule = self.get_rule_by_id(db, tenant_id, rule_id)
        db.delete(rule)
        db.commit()


detection_rule_service = DetectionRuleService()
