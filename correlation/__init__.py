"""
3 Sum Threat Detection correlation engine for blue_team_mcp.
© NAuliajati (TangerangKota-CSIRT)
Provides pure evaluation logic for:
- Engine A: Multi IoC Risk Thresholding (score aggregation across 3 alert categories)
- Engine B: 3 Source Volumetric Z-Score Anomaly Detection
All functions are stateless and testable without a Wazuh Indexer connection.
"""
