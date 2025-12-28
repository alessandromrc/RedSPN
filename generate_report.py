#!/usr/bin/env python3
"""
Active Directory Security Audit Report Generator
Processes JSON audit data and generates HTML report with risk scoring
"""

import json
import sys
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any

# HTML Template with local libraries
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active Directory Security Audit Report</title>
    <script src="libs/chart.umd.min.js"></script>
    <script type="text/javascript" src="libs/vis-network.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
            background: #f8f9fa;
            color: #212529;
            line-height: 1.6;
            font-size: 14px;
        }}
        
        .container {{
            max-width: 1600px;
            margin: 0 auto;
            padding: 0;
            background: #ffffff;
            box-shadow: 0 0 1px rgba(0,0,0,0.1);
        }}
        
        header {{
            background: #8b1a1a;
            color: #ffffff;
            padding: 40px 50px;
            border-bottom: 4px solid #a02020;
        }}
        
        header h1 {{
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }}
        
        .meta-info {{
            display: flex;
            gap: 30px;
            margin-top: 16px;
            font-size: 13px;
            color: #f5c2c7;
            flex-wrap: wrap;
        }}
        
        .meta-info span {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        
        .meta-info strong {{
            color: #ffffff;
            font-weight: 600;
        }}
        
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 0;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .card {{
            background: #ffffff;
            padding: 24px 28px;
            border-right: 1px solid #e9ecef;
            border-bottom: 1px solid #e9ecef;
            transition: background-color 0.15s ease;
        }}
        
        .card:last-child {{
            border-right: none;
        }}
        
        .card:hover {{
            background: #f8f9fa;
        }}
        
        .card h3 {{
            color: #6c757d;
            margin-bottom: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .card .value {{
            font-size: 32px;
            font-weight: 700;
            color: #212529;
            line-height: 1.2;
            margin-bottom: 8px;
        }}
        
        .risk-score {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 3px;
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .risk-low {{
            background: #d1e7dd;
            color: #0f5132;
            border: 1px solid #badbcc;
        }}
        
        .risk-medium {{
            background: #fff3cd;
            color: #664d03;
            border: 1px solid #ffecb5;
        }}
        
        .risk-high {{
            background: #f8d7da;
            color: #842029;
            border: 1px solid #f5c2c7;
        }}
        
        .section {{
            background: #ffffff;
            border-bottom: 1px solid #e9ecef;
            margin-bottom: 0;
        }}
        
        .section-header {{
            padding: 20px 50px;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background-color 0.15s ease;
        }}
        
        .section-header:hover {{
            background: #e9ecef;
        }}
        
        .section h2 {{
            color: #212529;
            font-size: 16px;
            font-weight: 600;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .section-icon {{
            font-size: 18px;
            opacity: 0.7;
        }}
        
        .section-toggle {{
            color: #6c757d;
            font-size: 12px;
            font-weight: 400;
            transition: transform 0.2s ease;
        }}
        
        .section.collapsed .section-toggle {{
            transform: rotate(-90deg);
        }}
        
        .section-content {{
            padding: 30px 50px;
            overflow: hidden;
            transition: max-height 0.3s ease-out, padding 0.3s ease-out;
        }}
        
        .section.collapsed .section-content {{
            max-height: 0;
            padding-top: 0;
            padding-bottom: 0;
            overflow: hidden;
        }}
        
        table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            margin-top: 0;
            font-size: 13px;
        }}
        
        th {{
            background: #f8f9fa;
            color: #495057;
            padding: 12px 14px;
            text-align: left;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid #dee2e6;
            position: sticky;
            top: 0;
            z-index: 10;
        }}
        
        td {{
            padding: 12px 14px;
            border-bottom: 1px solid #e9ecef;
            color: #212529;
        }}
        
        tbody tr {{
            transition: background-color 0.1s ease;
        }}
        
        tbody tr:hover {{
            background: #f8f9fa;
        }}
        
        tbody tr:last-child td {{
            border-bottom: none;
        }}
        
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 2px;
            font-size: 11px;
            font-weight: 600;
            margin: 1px 2px;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            border: 1px solid transparent;
        }}
        
        .badge-red {{
            background: #f8d7da;
            color: #721c24;
            border-color: #f5c2c7;
        }}
        
        .badge-yellow {{
            background: #fff3cd;
            color: #856404;
            border-color: #ffecb5;
        }}
        
        .badge-green {{
            background: #d1e7dd;
            color: #0f5132;
            border-color: #badbcc;
        }}
        
        .badge-blue {{
            background: #f8d7da;
            color: #721c24;
            border-color: #f5c2c7;
        }}
        
        .badge-gray {{
            background: #e9ecef;
            color: #495057;
            border-color: #dee2e6;
        }}
        
        .alert {{
            padding: 16px 20px;
            margin: 20px 0;
            border-left: 4px solid;
            border-radius: 0;
            background: #f8f9fa;
            font-size: 13px;
        }}
        
        .alert-warning {{
            border-left-color: #ffc107;
            background: #fffbf0;
            color: #856404;
        }}
        
        .alert-danger {{
            border-left-color: #dc3545;
            background: #fff5f5;
            color: #721c24;
        }}
        
        .alert-info {{
            border-left-color: #0dcaf0;
            background: #f0f9ff;
            color: #055160;
        }}
        
        .recommendations {{
            background: #f8f9fa;
            border-left: 4px solid #dc3545;
            padding: 24px 28px;
            margin: 0;
        }}
        
        .recommendations h3 {{
            color: #dc3545;
            margin-bottom: 16px;
            font-size: 15px;
            font-weight: 600;
        }}
        
        .recommendations ul {{
            margin-left: 20px;
            list-style: none;
        }}
        
        .recommendations li {{
            margin-bottom: 12px;
            padding-left: 24px;
            position: relative;
            font-size: 13px;
            line-height: 1.6;
            color: #495057;
        }}
        
        .recommendations li::before {{
            content: "→";
            position: absolute;
            left: 0;
            color: #dc3545;
            font-weight: bold;
        }}
        
        .recommendations li strong {{
            color: #212529;
            font-weight: 600;
        }}
        
        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin: 24px 0;
        }}
        
        .stat-item {{
            padding: 20px;
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 0;
        }}
        
        .stat-item .label {{
            font-size: 11px;
            color: #6c757d;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }}
        
        .stat-item .number {{
            font-size: 24px;
            font-weight: 700;
            color: #212529;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 24px 50px;
            border-top: 1px solid #e9ecef;
            text-align: center;
            font-size: 12px;
            color: #6c757d;
        }}
        
        #graph-container {{
            width: 100%;
            height: 800px;
            border: 1px solid #dee2e6;
            background: #ffffff;
            margin: 20px 0;
        }}
        
        .graph-controls {{
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }}
        
        .graph-controls button {{
            padding: 8px 16px;
            background: #dc3545;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: background-color 0.2s;
        }}
        
        .graph-controls button:hover {{
            background: #c82333;
        }}
        
        .graph-controls button.active {{
            background: #a02020;
        }}
        
        .graph-legend {{
            display: flex;
            gap: 20px;
            margin-top: 15px;
            flex-wrap: wrap;
            font-size: 12px;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 50%;
            border: 2px solid #dee2e6;
        }}
        
        .node-info-panel {{
            position: fixed;
            top: 50%;
            right: 20px;
            transform: translateY(-50%);
            background: white;
            border: 1px solid #dee2e6;
            padding: 20px;
            border-radius: 4px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            font-size: 13px;
            max-width: 350px;
            z-index: 1000;
            display: none;
        }}
        
        .node-info-panel.visible {{
            display: block;
        }}
        
        .node-info-panel h3 {{
            margin: 0 0 12px 0;
            color: #212529;
            font-size: 16px;
            border-bottom: 2px solid #dee2e6;
            padding-bottom: 8px;
        }}
        
        .node-info-panel .info-row {{
            margin: 8px 0;
            display: flex;
            justify-content: space-between;
        }}
        
        .node-info-panel .info-label {{
            font-weight: 600;
            color: #6c757d;
        }}
        
        .node-info-panel .info-value {{
            color: #212529;
        }}
        
        .node-info-panel .close-btn {{
            position: absolute;
            top: 10px;
            right: 10px;
            background: none;
            border: none;
            font-size: 20px;
            cursor: pointer;
            color: #6c757d;
            padding: 0;
            width: 24px;
            height: 24px;
            line-height: 24px;
        }}
        
        .node-info-panel .close-btn:hover {{
            color: #212529;
        }}
        
        @media print {{
            /* Reset margins and padding for print */
            * {{
                margin: 0;
                padding: 0;
            }}
            
            body {{
                background: white;
                color: black;
                font-size: 10pt;
                line-height: 1.4;
            }}
            
            .container {{
                max-width: 100%;
                padding: 0;
                margin: 0;
            }}
            
            /* Header styling for print */
            header {{
                background: white !important;
                color: black !important;
                border-bottom: 2px solid black;
                padding: 15px 20px;
                page-break-after: avoid;
            }}
            
            header h1 {{
                color: black !important;
                font-size: 18pt;
            }}
            
            /* Dashboard - make it compact */
            .dashboard {{
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 10px;
                margin: 15px 0;
                page-break-inside: avoid;
            }}
            
            .card {{
                background: white !important;
                border: 1px solid #000 !important;
                padding: 10px;
                page-break-inside: avoid;
            }}
            
            .card h3 {{
                font-size: 9pt;
                margin-bottom: 5px;
            }}
            
            .card .value {{
                font-size: 16pt;
                color: black !important;
            }}
            
            /* Sections */
            .section {{
                page-break-inside: avoid;
                margin-bottom: 15px;
            }}
            
            .section-header {{
                cursor: default;
                background: #f0f0f0 !important;
                color: black !important;
                border: 1px solid #000;
                padding: 8px 15px;
                page-break-after: avoid;
            }}
            
            .section-header h2 {{
                color: black !important;
                font-size: 12pt;
            }}
            
            .section-toggle {{
                display: none;
            }}
            
            .section-icon {{
                display: none;
            }}
            
            .section.collapsed .section-content {{
                max-height: none;
                padding: 15px 20px;
                display: block !important;
            }}
            
            .section-content {{
                display: block !important;
            }}
            
            /* Tables */
            .table-container {{
                overflow: visible;
            }}
            
            table {{
                width: 100%;
                border-collapse: collapse;
                font-size: 8pt;
                page-break-inside: auto;
            }}
            
            table thead {{
                display: table-header-group;
                background: #f0f0f0 !important;
            }}
            
            table tbody {{
                display: table-row-group;
            }}
            
            table tr {{
                page-break-inside: avoid;
                page-break-after: auto;
            }}
            
            table th, table td {{
                border: 1px solid #000 !important;
                padding: 4px 6px;
                color: black !important;
            }}
            
            table th {{
                background: #e0e0e0 !important;
                color: black !important;
                font-weight: bold;
            }}
            
            /* Badges - convert to text */
            .badge {{
                border: 1px solid #000 !important;
                background: white !important;
                color: black !important;
                padding: 2px 6px;
                font-size: 7pt;
            }}
            
            .badge-red, .badge-yellow, .badge-green, .badge-gray {{
                background: white !important;
                color: black !important;
                border: 1px solid #000 !important;
            }}
            
            /* Alerts */
            .alert {{
                border: 1px solid #000 !important;
                background: white !important;
                color: black !important;
                padding: 10px;
                margin: 10px 0;
            }}
            
            .alert-warning {{
                border-left: 4px solid #000 !important;
            }}
            
            .alert-info {{
                border-left: 4px solid #000 !important;
            }}
            
            /* Graph - hide or show static version */
            #graph-container {{
                display: none !important;
            }}
            
            .graph-controls {{
                display: none !important;
            }}
            
            .graph-legend {{
                display: none !important;
            }}
            
            .node-info-panel {{
                display: none !important;
            }}
            
            /* Hide interactive elements (except print button shows in print preview) */
            button:not(:focus) {{
                display: none !important;
            }}
            
            .graph-filter-btn {{
                display: none !important;
            }}
            
            /* Summary stats */
            .summary-stats {{
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 10px;
                margin: 10px 0;
            }}
            
            .stat-item {{
                border: 1px solid #000;
                padding: 8px;
                background: white !important;
            }}
            
            /* Footer */
            .footer {{
                background: white !important;
                color: black !important;
                border-top: 1px solid #000;
                padding: 10px;
                margin-top: 20px;
                page-break-inside: avoid;
            }}
            
            /* Page breaks */
            .section:not(:last-child) {{
                page-break-after: auto;
            }}
            
            h2, h3 {{
                page-break-after: avoid;
            }}
            
            /* Risk scores - ensure readable */
            .risk-score {{
                color: black !important;
                border: 1px solid #000 !important;
                background: white !important;
            }}
            
            /* Recommendations */
            .recommendations {{
                page-break-inside: avoid;
            }}
            
            /* Remove shadows and effects */
            * {{
                box-shadow: none !important;
                text-shadow: none !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <h1>Active Directory Security Audit Report</h1>
                <button onclick="window.print()" style="background: #dc3545; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-size: 14px; font-weight: 600; box-shadow: 0 2px 4px rgba(0,0,0,0.1); transition: background-color 0.2s;" onmouseover="this.style.background='#c82333'" onmouseout="this.style.background='#dc3545'">🖨️ Print Report</button>
            </div>
            <div class="meta-info">
                <span><strong>Domain:</strong> {domain}</span>
                <span><strong>Generated:</strong> {timestamp}</span>
                <span><strong>Report Version:</strong> 1.0</span>
            </div>
        </header>
        
        <div class="dashboard">
            <div class="card">
                <h3>Overall Risk Score</h3>
                <div class="value">{overall_risk_score}</div>
                <span class="risk-score {overall_risk_class}">{overall_risk_label}</span>
            </div>
            <div class="card">
                <h3>Total Users</h3>
                <div class="value">{total_users}</div>
            </div>
            <div class="card">
                <h3>Total Computers</h3>
                <div class="value">{total_computers}</div>
            </div>
            <div class="card">
                <h3>Kerberoast Targets</h3>
                <div class="value">{kerberoast_targets}</div>
            </div>
            <div class="card">
                <h3>Delegation Risks</h3>
                <div class="value">{delegation_risks}</div>
            </div>
            <div class="card">
                <h3>Weak Encryption</h3>
                <div class="value">{weak_encryption}</div>
            </div>
            <div class="card">
                <h3>Computers Checked</h3>
                <div class="value">{computers_checked}</div>
            </div>
        </div>
        
        {sections}
        
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Recommendations</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="recommendations">
                    <h3>Remediation Actions</h3>
                    {recommendations}
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>This report was generated by RedSPN - Active Directory Security Audit Tool</p>
        </div>
    </div>
    
    <script>
        // Collapsible sections
        document.querySelectorAll('.section-header').forEach(header => {{
            header.addEventListener('click', function() {{
                const section = this.parentElement;
                section.classList.toggle('collapsed');
                
                // Reinitialize graph if graph section is expanded
                if (section.id === 'graph-section' && !section.classList.contains('collapsed')) {{
                    setTimeout(initGraph, 100);
                }}
            }});
        }});
        
        // BloodHound-style graph visualization
        function initGraph() {{
            if (typeof graphNodes === 'undefined' || typeof graphEdges === 'undefined') {{
                return;
            }}
            
            const container = document.getElementById('graph-container');
            if (!container) return;
            
            const data = {{
                nodes: new vis.DataSet(graphNodes),
                edges: new vis.DataSet(graphEdges)
            }};
            
            const options = {{
                nodes: {{
                    shape: 'dot',
                    size: 16,
                    font: {{
                        size: 12,
                        face: 'Segoe UI'
                    }},
                    borderWidth: 2,
                    shadow: true
                }},
                edges: {{
                    width: 2,
                    color: {{ color: '#848484' }},
                    smooth: {{
                        type: 'continuous',
                        roundness: 0.5
                    }},
                    arrows: {{
                        to: {{ enabled: true, scaleFactor: 0.8 }}
                    }},
                    font: {{
                        size: 10,
                        align: 'middle'
                    }}
                }},
                physics: {{
                    enabled: true,
                    stabilization: {{
                        iterations: 200
                    }},
                    barnesHut: {{
                        gravitationalConstant: -2000,
                        centralGravity: 0.1,
                        springLength: 200,
                        springConstant: 0.04,
                        damping: 0.09
                    }}
                }},
                interaction: {{
                    hover: true,
                    tooltipDelay: 200,
                    zoomView: true,
                    dragView: true
                }}
            }};
            
            const network = new vis.Network(container, data, options);
            
            // Filter controls
            const filterButtons = document.querySelectorAll('.graph-filter-btn');
            filterButtons.forEach(btn => {{
                btn.addEventListener('click', function() {{
                    const filterType = this.dataset.filter;
                    filterButtons.forEach(b => b.classList.remove('active'));
                    this.classList.add('active');
                    
                    let visibleNodes, visibleEdges;
                    
                    if (filterType === 'attack-paths') {{
                        // Show nodes involved in attack paths
                        const pathNodeIds = new Set();
                        if (typeof attackPaths !== 'undefined') {{
                            attackPaths.forEach(path => {{
                                path.path.forEach(nodeId => pathNodeIds.add(nodeId));
                            }});
                        }}
                        visibleNodes = graphNodes.filter(n => pathNodeIds.has(n.id)).map(n => n.id);
                        visibleEdges = graphEdges.filter(edge => {{
                            return visibleNodes.includes(edge.from) && visibleNodes.includes(edge.to);
                        }});
                        // Highlight attack path edges
                        visibleEdges.forEach(edge => {{
                            if (edge.attackPath) {{
                                edge.width = 4;
                                edge.color = '#dc3545';
                            }}
                        }});
                    }} else {{
                        visibleNodes = graphNodes.filter(node => {{
                            if (filterType === 'all') return true;
                            if (filterType === 'high-risk') {{
                                return node.risk === 'high' || node.group === 'Domain Admins' || node.group === 'Enterprise Admins';
                            }}
                            return node.type === filterType;
                        }}).map(n => n.id);
                        
                        visibleEdges = graphEdges.filter(edge => {{
                            return visibleNodes.includes(edge.from) && visibleNodes.includes(edge.to);
                        }});
                    }}
                    
                    data.nodes.update(graphNodes.filter(n => visibleNodes.includes(n.id)));
                    data.edges.update(visibleEdges);
                }});
            }});
            
            // Node click handler - show info panel instead of alert
            network.on('click', function(params) {{
                const panel = document.getElementById('node-info-panel');
                const titleEl = document.getElementById('node-info-title');
                const contentEl = document.getElementById('node-info-content');
                
                if (params.nodes.length > 0) {{
                    const nodeId = params.nodes[0];
                    const node = graphNodes.find(n => n.id === nodeId);
                    if (node) {{
                        titleEl.textContent = node.label;
                        let html = '';
                        html += '<div class="info-row"><span class="info-label">Type:</span><span class="info-value">' + node.type + '</span></div>';
                        if (node.group) {{
                            html += '<div class="info-row"><span class="info-label">Group:</span><span class="info-value">' + node.group + '</span></div>';
                        }}
                        if (node.risk) {{
                            const riskColor = node.risk === 'high' ? '#dc3545' : node.risk === 'medium' ? '#ffc107' : '#e74c3c';
                            html += '<div class="info-row"><span class="info-label">Risk:</span><span class="info-value" style="color: ' + riskColor + '; font-weight: 600;">' + node.risk.toUpperCase() + '</span></div>';
                        }}
                        if (node.spns !== undefined && node.spns > 0) {{
                            html += '<div class="info-row"><span class="info-label">SPNs:</span><span class="info-value">' + node.spns + '</span></div>';
                        }}
                        if (node.type === 'user' && typeof userData !== 'undefined') {{
                            // Find user in data to show more details
                            const user = userData.find(u => 'user_' + u.SamAccountName === nodeId);
                            if (user) {{
                                if (user.PasswordLastSet) {{
                                    html += '<div class="info-row"><span class="info-label">Password Last Set:</span><span class="info-value">' + user.PasswordLastSet + '</span></div>';
                                }}
                                if (user.TrustedForDelegation || user.TrustedToAuthForDelegation) {{
                                    html += '<div class="info-row"><span class="info-label">Delegation:</span><span class="info-value" style="color: #dc3545;">Enabled</span></div>';
                                }}
                                if (user.SPNs && user.SPNs.length > 0) {{
                                    html += '<div class="info-row"><span class="info-label">SPN Count:</span><span class="info-value">' + user.SPNs.length + '</span></div>';
                                }}
                            }}
                        }}
                        contentEl.innerHTML = html;
                        panel.classList.add('visible');
                    }}
                }} else {{
                    // Click on empty space - hide panel
                    panel.classList.remove('visible');
                }}
            }});
            
            // Hide panel when clicking outside
            network.on('oncontext', function(params) {{
                document.getElementById('node-info-panel').classList.remove('visible');
            }});
        }}
        
        // Initialize graph when page loads
        if (document.readyState === 'loading') {{
            document.addEventListener('DOMContentLoaded', initGraph);
        }} else {{
            initGraph();
        }}
    </script>
</body>
</html>
"""


class ADAuditReportGenerator:
    def __init__(self, json_data: Dict[str, Any]):
        self.data = json_data
        self.risk_scores = {}
        self.recommendations = []
    
    def _get_member_of(self, user: Dict[str, Any]) -> List[str]:
        """Safely get MemberOf list, handling None values"""
        member_of = user.get('MemberOf')
        if member_of is None:
            return []
        if isinstance(member_of, list):
            return member_of
        return []
        
    def calculate_risk_scores(self) -> Dict[str, int]:
        """Calculate risk scores for different categories"""
        scores = {
            'kerberoasting': 0,
            'delegation': 0,
            'encryption': 0,
            'ntlm': 0,
            'privileged': 0,
            'inactive': 0
        }
        
        # Kerberoasting risk (SPNs on user accounts)
        users_with_spns = [u for u in self.data.get('Users', []) if u.get('SPNs') and len(u.get('SPNs', [])) > 0]
        scores['kerberoasting'] = len(users_with_spns) * 10
        
        # Delegation risk
        users_with_delegation = [u for u in self.data.get('Users', []) 
                                if u.get('TrustedForDelegation') or u.get('TrustedToAuthForDelegation')]
        computers_with_delegation = [c for c in self.data.get('Computers', [])
                                    if (c.get('TrustedForDelegation') or c.get('TrustedToAuthForDelegation') or 
                                        (c.get('ConstrainedDelegation') and len(c.get('ConstrainedDelegation', [])) > 0))
                                    and not c.get('IsDomainController', False)]
        scores['delegation'] = (len(users_with_delegation) * 15) + (len(computers_with_delegation) * 20)
        
        # Encryption risk (DES, RC4, reversible)
        weak_encryption_users = [u for u in self.data.get('Users', [])
                               if any(enc in ['DES', 'RC4'] for enc in u.get('EncryptionTypes', []))
                               or u.get('UseDESKeyOnly', False)]
        scores['encryption'] = len(weak_encryption_users) * 5
        
        # NTLM risk
        scores['ntlm'] = min(self.data.get('Statistics', {}).get('NTLMEventCount', 0) * 2, 100)
        
        # Privileged account risk
        domain_admins = [u for u in self.data.get('Users', [])
                        if 'Domain Admins' in self._get_member_of(u)]
        unprotected_admins = [u for u in domain_admins
                            if 'Protected Users' not in self._get_member_of(u)]
        scores['privileged'] = len(unprotected_admins) * 25
        
        # Inactive accounts
        inactive_users = [u for u in self.data.get('Users', [])
                         if u.get('DaysSinceLastLogon') and u.get('DaysSinceLastLogon') > 90]
        old_passwords = [u for u in self.data.get('Users', [])
                        if u.get('DaysSincePasswordChange') and u.get('DaysSincePasswordChange') > 365]
        scores['inactive'] = (len(inactive_users) * 2) + (len(old_passwords) * 3)
        
        self.risk_scores = scores
        return scores
    
    def get_overall_risk_score(self) -> tuple:
        """Calculate overall risk score (0-100)"""
        total_score = sum(self.risk_scores.values())
        # Normalize to 0-100 scale (cap at 100)
        normalized_score = min(total_score / 10, 100)
        
        if normalized_score < 30:
            return (int(normalized_score), 'risk-low', 'Low Risk')
        elif normalized_score < 70:
            return (int(normalized_score), 'risk-medium', 'Medium Risk')
        else:
            return (int(normalized_score), 'risk-high', 'High Risk')
    
    def generate_user_table(self) -> str:
        """Generate HTML table for user accounts with risks"""
        users = self.data.get('Users', [])
        
        # Sort by risk (users with SPNs, delegation, weak encryption first)
        def risk_sort_key(u):
            risk = 0
            if u.get('SPNs') and len(u.get('SPNs', [])) > 0:
                risk += 1000
            if u.get('TrustedForDelegation') or u.get('TrustedToAuthForDelegation'):
                risk += 500
            if any(enc in ['DES', 'RC4'] for enc in u.get('EncryptionTypes', [])):
                risk += 200
            if 'Domain Admins' in self._get_member_of(u):
                risk += 300
            return -risk
        
        sorted_users = sorted(users, key=risk_sort_key)
        
        rows = []
        for user in sorted_users[:500]:  # Limit to 500 for performance
            spn_badge = ''
            if user.get('SPNs') and len(user.get('SPNs', [])) > 0:
                spn_badge = '<span class="badge badge-red">SPN</span>'
            
            delegation_badge = ''
            if user.get('TrustedForDelegation'):
                delegation_badge = '<span class="badge badge-red">Unconstrained</span>'
            elif user.get('TrustedToAuthForDelegation'):
                delegation_badge = '<span class="badge badge-yellow">Constrained</span>'
            
            encryption_badge = ''
            enc_types = user.get('EncryptionTypes', [])
            if 'DES' in enc_types or user.get('UseDESKeyOnly'):
                encryption_badge = '<span class="badge badge-red">DES</span>'
            elif 'RC4' in enc_types:
                encryption_badge = '<span class="badge badge-yellow">RC4</span>'
            elif 'AES256' in enc_types and 'AES128' in enc_types:
                encryption_badge = '<span class="badge badge-green">AES</span>'
            
            admin_badge = ''
            member_of = self._get_member_of(user)
            if 'Domain Admins' in member_of:
                admin_badge = '<span class="badge badge-red">DA</span>'
            if 'Enterprise Admins' in member_of:
                admin_badge += '<span class="badge badge-red">EA</span>'
            if 'Protected Users' in member_of:
                admin_badge += '<span class="badge badge-green">Protected</span>'
            
            pwd_age = user.get('DaysSincePasswordChange', 'N/A')
            if isinstance(pwd_age, (int, float)) and pwd_age > 365:
                pwd_age = f'<span style="color: red; font-weight: bold;">{int(pwd_age)}</span>'
            
            rows.append(f"""
                <tr>
                    <td>{user.get('SamAccountName', 'N/A')}</td>
                    <td>{user.get('DisplayName', 'N/A')}</td>
                    <td>{spn_badge} {delegation_badge} {encryption_badge} {admin_badge}</td>
                    <td>{', '.join(user.get('SPNs', []))[:50] or 'None'}</td>
                    <td>{user.get('PasswordLastSet', 'Never')}</td>
                    <td>{pwd_age}</td>
                    <td>{'Yes' if user.get('PasswordNeverExpires') else 'No'}</td>
                    <td>{', '.join(self._get_member_of(user)) or 'None'}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> User Accounts ({len(users)} total)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>Account</th>
                            <th>Display Name</th>
                            <th>Risks</th>
                            <th>SPNs</th>
                            <th>Password Last Set</th>
                            <th>Days Since Change</th>
                            <th>Never Expires</th>
                            <th>Groups</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_computer_table(self) -> str:
        """Generate HTML table for computer accounts"""
        computers = self.data.get('Computers', [])
        
        rows = []
        for computer in computers[:500]:  # Limit to 500
            delegation_badge = ''
            if computer.get('TrustedForDelegation'):
                delegation_badge = '<span class="badge badge-red">Unconstrained</span>'
            elif computer.get('TrustedToAuthForDelegation') or (computer.get('ConstrainedDelegation') and len(computer.get('ConstrainedDelegation', [])) > 0):
                delegation_badge = '<span class="badge badge-yellow">Constrained</span>'
            
            if computer.get('IsDomainController'):
                delegation_badge += '<span class="badge badge-blue">DC</span>'
            
            encryption_badge = ''
            enc_types = computer.get('EncryptionTypes', [])
            if 'DES' in enc_types:
                encryption_badge = '<span class="badge badge-red">DES</span>'
            elif 'RC4' in enc_types:
                encryption_badge = '<span class="badge badge-yellow">RC4</span>'
            
            rows.append(f"""
                <tr>
                    <td>{computer.get('SamAccountName', 'N/A')}</td>
                    <td>{computer.get('OperatingSystem', 'N/A')}</td>
                    <td>{delegation_badge} {encryption_badge}</td>
                    <td>{', '.join(computer.get('SPNs', []))[:50] or 'None'}</td>
                    <td>{', '.join(computer.get('ConstrainedDelegation', []))[:50] or 'None'}</td>
                    <td>{', '.join(enc_types) or 'None'}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Computer Accounts ({len(computers)} total)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>Computer</th>
                            <th>OS</th>
                            <th>Risks</th>
                            <th>SPNs</th>
                            <th>Constrained Delegation</th>
                            <th>Encryption Types</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_service_accounts_table(self) -> str:
        """Generate HTML table for service accounts"""
        service_accounts = self.data.get('ServiceAccounts', [])
        
        rows = []
        for svc in service_accounts:
            spn_badge = ''
            if svc.get('SPNs') and len(svc.get('SPNs', [])) > 0:
                spn_badge = '<span class="badge badge-red">SPN</span>'
            
            rows.append(f"""
                <tr>
                    <td>{svc.get('Type', 'N/A')}</td>
                    <td>{svc.get('SamAccountName', 'N/A')}</td>
                    <td>{spn_badge}</td>
                    <td>{', '.join(svc.get('SPNs', []))[:100] or 'None'}</td>
                    <td>{'Yes' if svc.get('TrustedForDelegation') or svc.get('TrustedToAuthForDelegation') else 'No'}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Service Accounts ({len(service_accounts)} total)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Account</th>
                            <th>Risks</th>
                            <th>SPNs</th>
                            <th>Delegation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_kerberoast_table(self) -> str:
        """Generate table of Kerberoast targets"""
        users = [u for u in self.data.get('Users', []) 
                if u.get('SPNs') and len(u.get('SPNs', [])) > 0]
        
        rows = []
        for user in users:
            rows.append(f"""
                <tr>
                    <td>{user.get('SamAccountName', 'N/A')}</td>
                    <td>{', '.join(user.get('SPNs', []))}</td>
                    <td>{user.get('PasswordLastSet', 'Never')}</td>
                    <td>{user.get('DaysSincePasswordChange', 'N/A')}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Kerberoast Targets ({len(users)} accounts)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-danger">
                    <strong>Security Risk:</strong> These accounts have SPNs and are vulnerable to Kerberoasting attacks.
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Account</th>
                            <th>SPNs</th>
                            <th>Password Last Set</th>
                            <th>Days Since Change</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_delegation_table(self) -> str:
        """Generate table of delegation risks"""
        users = [u for u in self.data.get('Users', [])
                if u.get('TrustedForDelegation') or u.get('TrustedToAuthForDelegation')]
        computers = [c for c in self.data.get('Computers', [])
                    if (c.get('TrustedForDelegation') or c.get('TrustedToAuthForDelegation') or 
                        (c.get('ConstrainedDelegation') and len(c.get('ConstrainedDelegation', [])) > 0))
                    and not c.get('IsDomainController', False)]
        
        rows = []
        for user in users:
            delegation_type = 'Unconstrained' if user.get('TrustedForDelegation') else 'Constrained'
            rows.append(f"""
                <tr>
                    <td>User</td>
                    <td>{user.get('SamAccountName', 'N/A')}</td>
                    <td><span class="badge badge-red">{delegation_type}</span></td>
                    <td>{', '.join(user.get('SPNs', []))[:50] or 'None'}</td>
                </tr>
            """)
        
        for computer in computers:
            delegation_type = 'Unconstrained' if computer.get('TrustedForDelegation') else 'Constrained'
            rows.append(f"""
                <tr>
                    <td>Computer</td>
                    <td>{computer.get('SamAccountName', 'N/A')}</td>
                    <td><span class="badge badge-red">{delegation_type}</span></td>
                    <td>{', '.join(computer.get('ConstrainedDelegation', []))[:50] or 'None'}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Delegation Risks ({len(users) + len(computers)} accounts)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-danger">
                    <strong>Security Risk:</strong> These accounts have delegation enabled, which can be abused for privilege escalation.
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Account</th>
                            <th>Delegation Type</th>
                            <th>Allowed To Delegate To</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_encryption_table(self) -> str:
        """Generate table of weak encryption settings"""
        users = [u for u in self.data.get('Users', [])
                if any(enc in ['DES', 'RC4'] for enc in u.get('EncryptionTypes', []))
                or u.get('UseDESKeyOnly', False)]
        
        rows = []
        for user in users:
            weak_types = [enc for enc in user.get('EncryptionTypes', []) if enc in ['DES', 'RC4']]
            if user.get('UseDESKeyOnly'):
                weak_types.append('DES (forced)')
            
            rows.append(f"""
                <tr>
                    <td>{user.get('SamAccountName', 'N/A')}</td>
                    <td><span class="badge badge-red">{', '.join(weak_types)}</span></td>
                    <td>{', '.join(user.get('EncryptionTypes', []))}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Weak Encryption ({len(users)} accounts)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-warning">
                    <strong>Security Risk:</strong> These accounts support weak encryption types (DES/RC4) that are vulnerable to attacks.
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Account</th>
                            <th>Weak Types</th>
                            <th>All Types</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_privileged_accounts_table(self) -> str:
        """Generate table of privileged accounts"""
        domain_admins = [u for u in self.data.get('Users', [])
                        if 'Domain Admins' in self._get_member_of(u)]
        enterprise_admins = [u for u in self.data.get('Users', [])
                            if 'Enterprise Admins' in self._get_member_of(u)]
        
        all_privileged = list(set([u['SamAccountName'] for u in domain_admins + enterprise_admins]))
        privileged_users = [u for u in self.data.get('Users', [])
                           if u.get('SamAccountName') in all_privileged]
        
        rows = []
        for user in privileged_users:
            groups = self._get_member_of(user)
            protected = 'Yes' if 'Protected Users' in groups else '<span style="color: red; font-weight: bold;">No</span>'
            
            rows.append(f"""
                <tr>
                    <td>{user.get('SamAccountName', 'N/A')}</td>
                    <td>{', '.join([g for g in groups if g in ['Domain Admins', 'Enterprise Admins']])}</td>
                    <td>{protected}</td>
                    <td>{user.get('PasswordLastSet', 'Never')}</td>
                    <td>{user.get('DaysSincePasswordChange', 'N/A')}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Privileged Accounts ({len(privileged_users)} accounts)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>Account</th>
                            <th>Groups</th>
                            <th>Protected Users</th>
                            <th>Password Last Set</th>
                            <th>Days Since Change</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_inactive_accounts_table(self) -> str:
        """Generate table of inactive accounts and old passwords"""
        inactive = [u for u in self.data.get('Users', [])
                   if u.get('DaysSinceLastLogon') and u.get('DaysSinceLastLogon') > 90]
        old_passwords = [u for u in self.data.get('Users', [])
                        if u.get('DaysSincePasswordChange') and u.get('DaysSincePasswordChange') > 365]
        
        rows = []
        for user in inactive:
            rows.append(f"""
                <tr>
                    <td>{user.get('SamAccountName', 'N/A')}</td>
                    <td><span class="badge badge-yellow">Inactive</span></td>
                    <td>{user.get('DaysSinceLastLogon', 'N/A')} days</td>
                    <td>{user.get('LastLogonDate', 'Never')}</td>
                </tr>
            """)
        
        for user in old_passwords:
            if user.get('SamAccountName') not in [u.get('SamAccountName') for u in inactive]:
                rows.append(f"""
                    <tr>
                        <td>{user.get('SamAccountName', 'N/A')}</td>
                        <td><span class="badge badge-yellow">Old Password</span></td>
                        <td>{user.get('DaysSincePasswordChange', 'N/A')} days</td>
                        <td>{user.get('PasswordLastSet', 'Never')}</td>
                    </tr>
                """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Inactive Accounts & Old Passwords ({len(inactive) + len(old_passwords)} accounts)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>Account</th>
                            <th>Issue</th>
                            <th>Days</th>
                            <th>Last Activity</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_krbtgt_info(self) -> str:
        """Generate krbtgt account information"""
        krbtgt = self.data.get('KrbtgtInfo')
        if not krbtgt:
            return ""
        
        days = krbtgt.get('DaysSincePasswordChange', 0)
        status_badge = '<span class="badge badge-green">OK</span>' if days < 180 else '<span class="badge badge-red">CRITICAL</span>'
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> krbtgt Account Status</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="summary-stats">
                    <div class="stat-item">
                        <div class="label">Password Last Set</div>
                        <div class="number">{krbtgt.get('PasswordLastSet', 'Never')}</div>
                    </div>
                    <div class="stat-item">
                        <div class="label">Days Since Change</div>
                        <div class="number">{days}</div>
                    </div>
                    <div class="stat-item">
                        <div class="label">Status</div>
                        <div class="number">{status_badge}</div>
                    </div>
                </div>
                <div class="alert {'alert-warning' if days >= 150 else 'alert-info'}" style="margin-top: 20px;">
                    {'<strong>Action Required:</strong> krbtgt password should be changed every 180 days. Consider rotating it soon.' if days >= 150 else '<strong>Status:</strong> krbtgt password is within acceptable age.'}
                </div>
            </div>
        </div>
        """
    
    def generate_ntlm_info(self) -> str:
        """Generate NTLM usage information"""
        events = self.data.get('NTLMEvents', [])
        event_count = len(events)
        
        if not events or event_count == 0:
            return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> NTLM Usage Analysis</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="summary-stats">
                    <div class="stat-item">
                        <div class="label">Recent NTLM Events</div>
                        <div class="number">0</div>
                    </div>
                </div>
                <div class="alert alert-info" style="margin-top: 20px;">
                    <strong>Status:</strong> No recent NTLM authentication events detected in Security Event Log (Event ID 4624).
                    <p style="margin-top: 10px; font-size: 0.9em;">This may indicate:</p>
                    <ul style="margin-top: 5px; margin-left: 20px; font-size: 0.9em;">
                        <li>No NTLM authentication occurred recently</li>
                        <li>Security Event Log access requires elevated permissions</li>
                        <li>Event log may be cleared or rotated</li>
                        <li>NTLM authentication is disabled or blocked</li>
                    </ul>
                </div>
            </div>
        </div>
        """
        
        # Group events by account for summary
        account_counts = {}
        ip_counts = {}
        for event in events:
            account = f"{event.get('AccountDomain', '')}\\{event.get('AccountName', 'N/A')}"
            account_counts[account] = account_counts.get(account, 0) + 1
            ip = event.get('IPAddress', 'N/A')
            if ip and ip != '-':
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        # Sort by count
        top_accounts = sorted(account_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Generate event table rows
        rows = []
        for event in events[:100]:  # Limit to 100 for display
            account = f"{event.get('AccountDomain', '')}\\{event.get('AccountName', 'N/A')}"
            logon_type = event.get('LogonType', 'N/A')
            auth_package = event.get('AuthenticationPackageName', 'N/A')
            # Determine if likely NTLM based on auth package
            is_ntlm = 'NTLM' in (auth_package or '').upper() or logon_type in ['2', '3']
            ntlm_badge = '<span class="badge badge-red">NTLM</span>' if is_ntlm else '<span class="badge badge-gray">Other</span>'
            
            rows.append(f"""
                <tr>
                    <td>{event.get('TimeCreated', 'N/A')}</td>
                    <td>{account}</td>
                    <td>{event.get('IPAddress', 'N/A')}</td>
                    <td>{event.get('WorkstationName', 'N/A')}</td>
                    <td>{logon_type}</td>
                    <td>{auth_package}</td>
                    <td>{ntlm_badge}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> NTLM Usage Analysis</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="summary-stats">
                    <div class="stat-item">
                        <div class="label">Recent NTLM Events</div>
                        <div class="number">{event_count}</div>
                    </div>
                    <div class="stat-item">
                        <div class="label">Unique Accounts</div>
                        <div class="number">{len(account_counts)}</div>
                    </div>
                    <div class="stat-item">
                        <div class="label">Source IPs</div>
                        <div class="number">{len(ip_counts)}</div>
                    </div>
                </div>
                
                <div class="alert alert-warning" style="margin-top: 20px;">
                    <strong>Recommendation:</strong> NTLM authentication detected. Consider migrating to Kerberos where possible. 
                    NTLM is less secure than Kerberos and should be disabled when not needed.
                </div>
                
                {f'''
                <div style="margin-top: 30px;">
                    <h3 style="font-size: 14px; margin-bottom: 10px; color: #495057;">Top Accounts Using NTLM</h3>
                    <table class="data-table" style="margin-bottom: 20px;">
                        <thead>
                            <tr>
                                <th>Account</th>
                                <th>Event Count</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join([f'<tr><td>{acc}</td><td>{count}</td></tr>' for acc, count in top_accounts])}
                        </tbody>
                    </table>
                </div>
                ''' if top_accounts else ''}
                
                {f'''
                <div style="margin-top: 20px;">
                    <h3 style="font-size: 14px; margin-bottom: 10px; color: #495057;">Top Source IP Addresses</h3>
                    <table class="data-table" style="margin-bottom: 20px;">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Event Count</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join([f'<tr><td>{ip}</td><td>{count}</td></tr>' for ip, count in top_ips])}
                        </tbody>
                    </table>
                </div>
                ''' if top_ips else ''}
                
                <div style="margin-top: 30px;">
                    <h3 style="font-size: 14px; margin-bottom: 10px; color: #495057;">Recent NTLM Authentication Events</h3>
                    <p style="font-size: 0.9em; color: #666; margin-bottom: 10px;">Showing last {min(100, event_count)} events from Security Event Log (Event ID 4624)</p>
                    <div class="table-container">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Account</th>
                                    <th>IP Address</th>
                                    <th>Workstation</th>
                                    <th>Logon Type</th>
                                    <th>Auth Package</th>
                                    <th>Type</th>
                                </tr>
                            </thead>
                            <tbody>
                                {''.join(rows)}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def generate_password_policy_table(self) -> str:
        """Generate password policy information"""
        policy = self.data.get('PasswordPolicy')
        if not policy:
            return ""
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Password Policy</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>Setting</th>
                            <th>Value</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Minimum Password Length</td>
                            <td>{policy.get('MinPasswordLength', 'N/A')}</td>
                            <td>{'<span class="badge badge-green">Good</span>' if policy.get('MinPasswordLength', 0) >= 14 else '<span class="badge badge-yellow">Weak</span>' if policy.get('MinPasswordLength', 0) >= 8 else '<span class="badge badge-red">Critical</span>'}</td>
                        </tr>
                        <tr>
                            <td>Password History Count</td>
                            <td>{policy.get('PasswordHistoryCount', 'N/A')}</td>
                            <td>{'<span class="badge badge-green">Good</span>' if policy.get('PasswordHistoryCount', 0) >= 12 else '<span class="badge badge-yellow">Weak</span>'}</td>
                        </tr>
                        <tr>
                            <td>Maximum Password Age (days)</td>
                            <td>{policy.get('MaxPasswordAge', 'N/A')}</td>
                            <td>{'<span class="badge badge-green">Good</span>' if policy.get('MaxPasswordAge') and 30 <= policy.get('MaxPasswordAge') <= 90 else '<span class="badge badge-yellow">Review</span>' if policy.get('MaxPasswordAge') else '<span class="badge badge-gray">Not Set</span>'}</td>
                        </tr>
                        <tr>
                            <td>Minimum Password Age (days)</td>
                            <td>{policy.get('MinPasswordAge', 'N/A')}</td>
                            <td>{'<span class="badge badge-green">Good</span>' if policy.get('MinPasswordAge', 0) >= 1 else '<span class="badge badge-yellow">Weak</span>'}</td>
                        </tr>
                        <tr>
                            <td>Complexity Enabled</td>
                            <td>{'Yes' if policy.get('ComplexityEnabled') else 'No'}</td>
                            <td>{'<span class="badge badge-green">Enabled</span>' if policy.get('ComplexityEnabled') else '<span class="badge badge-red">Disabled</span>'}</td>
                        </tr>
                        <tr>
                            <td>Reversible Encryption</td>
                            <td>{'Yes' if policy.get('ReversibleEncryptionEnabled') else 'No'}</td>
                            <td>{'<span class="badge badge-red">CRITICAL</span>' if policy.get('ReversibleEncryptionEnabled') else '<span class="badge badge-green">Disabled</span>'}</td>
                        </tr>
                        <tr>
                            <td>Lockout Threshold</td>
                            <td>{policy.get('LockoutThreshold', 'N/A')}</td>
                            <td>{'<span class="badge badge-green">Good</span>' if policy.get('LockoutThreshold') and 3 <= policy.get('LockoutThreshold') <= 10 else '<span class="badge badge-yellow">Review</span>' if policy.get('LockoutThreshold') else '<span class="badge badge-red">Not Set</span>'}</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_domain_controllers_table(self) -> str:
        """Generate domain controllers table"""
        dcs = self.data.get('DomainControllers', [])
        if not dcs:
            return ""
        
        rows = []
        for dc in dcs:
            gc_badge = '<span class="badge badge-blue">GC</span>' if dc.get('IsGlobalCatalog') else ''
            ro_badge = '<span class="badge badge-yellow">RO</span>' if dc.get('IsReadOnly') else ''
            
            rows.append(f"""
                <tr>
                    <td>{dc.get('Name', 'N/A')}</td>
                    <td>{dc.get('HostName', 'N/A')}</td>
                    <td>{dc.get('IPv4Address', 'N/A')}</td>
                    <td>{dc.get('OperatingSystem', 'N/A')}</td>
                    <td>{dc.get('Site', 'N/A')}</td>
                    <td>{gc_badge} {ro_badge}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Domain Controllers ({len(dcs)} total)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Hostname</th>
                            <th>IP Address</th>
                            <th>Operating System</th>
                            <th>Site</th>
                            <th>Flags</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_trust_relationships_table(self) -> str:
        """Generate trust relationships table"""
        trusts = self.data.get('TrustRelationships', [])
        if not trusts:
            return ""
        
        rows = []
        for trust in trusts:
            direction_badge = '<span class="badge badge-blue">Inbound</span>' if trust.get('Direction') == 'Inbound' else '<span class="badge badge-green">Outbound</span>' if trust.get('Direction') == 'Outbound' else '<span class="badge badge-gray">Bidirectional</span>'
            selective_auth = '<span class="badge badge-green">Yes</span>' if trust.get('SelectiveAuthentication') else '<span class="badge badge-yellow">No</span>'
            
            rows.append(f"""
                <tr>
                    <td>{trust.get('Name', 'N/A')}</td>
                    <td>{trust.get('Target', 'N/A')}</td>
                    <td>{direction_badge}</td>
                    <td>{trust.get('TrustType', 'N/A')}</td>
                    <td>{selective_auth}</td>
                    <td>{'<span class="badge badge-green">Enabled</span>' if trust.get('SIDFilteringForestAware') else '<span class="badge badge-yellow">Disabled</span>'}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Trust Relationships ({len(trusts)} total)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-info">
                    <strong>Security Note:</strong> Review trust relationships regularly. Ensure SID filtering is enabled and use selective authentication where possible.
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Target Domain</th>
                            <th>Direction</th>
                            <th>Type</th>
                            <th>Selective Auth</th>
                            <th>SID Filtering</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_security_groups_table(self) -> str:
        """Generate security groups table"""
        groups = self.data.get('SecurityGroups', [])
        if not groups:
            return ""
        
        rows = []
        for group in groups:
            scope_badge = '<span class="badge badge-blue">Domain</span>' if group.get('GroupScope') == 'Domain' else '<span class="badge badge-green">Global</span>' if group.get('GroupScope') == 'Global' else '<span class="badge badge-gray">Universal</span>'
            member_count = group.get('MemberCount', 0)
            member_badge = f'<span class="badge {"badge-red" if member_count > 20 else "badge-yellow" if member_count > 10 else "badge-green"}">{member_count} members</span>'
            
            rows.append(f"""
                <tr>
                    <td>{group.get('Name', 'N/A')}</td>
                    <td>{group.get('Description', 'N/A')}</td>
                    <td>{scope_badge}</td>
                    <td>{member_badge}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Privileged Security Groups ({len(groups)} groups)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>Group Name</th>
                            <th>Description</th>
                            <th>Scope</th>
                            <th>Members</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_graph_visualization(self) -> str:
        """Generate BloodHound-style interactive graph visualization"""
        nodes = []
        edges = []
        node_id_map = {}
        node_counter = 1
        
        # Add domain node
        domain = self.data.get('Domain', 'DOMAIN')
        domain_id = f"domain_{domain}"
        node_id_map[domain_id] = domain_id
        nodes.append({
            'id': domain_id,
            'label': domain,
            'type': 'domain',
            'group': 'domain',
            'color': {'background': '#dc3545', 'border': '#842029'},
            'shape': 'box',
            'size': 30
        })
        
        # Add users (limit to high-risk users for performance)
        high_risk_users = []
        for user in self.data.get('Users', []):
            risk = 'low'
            if user.get('SPNs') and len(user.get('SPNs', [])) > 0:
                risk = 'high'
            elif user.get('TrustedForDelegation') or user.get('TrustedToAuthForDelegation'):
                risk = 'high'
            elif 'Domain Admins' in self._get_member_of(user) or 'Enterprise Admins' in self._get_member_of(user):
                risk = 'high'
            elif any(enc in ['DES', 'RC4'] for enc in user.get('EncryptionTypes', [])):
                risk = 'medium'
            
            if risk in ['high', 'medium'] or 'Domain Admins' in self._get_member_of(user):
                user_id = f"user_{user.get('SamAccountName')}"
                node_id_map[user_id] = user_id
                color = '#dc3545' if risk == 'high' else '#ffc107' if risk == 'medium' else '#e74c3c'
                nodes.append({
                    'id': user_id,
                    'label': user.get('SamAccountName', 'N/A'),
                    'type': 'user',
                    'group': ', '.join([g for g in self._get_member_of(user) if g in ['Domain Admins', 'Enterprise Admins']]) or 'user',
                    'risk': risk,
                    'spns': len(user.get('SPNs', [])) if user.get('SPNs') else 0,
                    'color': {'background': color, 'border': '#000'},
                    'size': 20 if risk == 'high' else 16
                })
                # Connect user to domain
                edges.append({
                    'from': domain_id,
                    'to': user_id,
                    'label': 'Member',
                    'color': '#848484'
                })
                high_risk_users.append(user)
        
        # Add security groups
        for group in self.data.get('SecurityGroups', []):
            group_name = group.get('Name', '')
            if group_name in ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Account Operators']:
                group_id = f"group_{group_name}"
                node_id_map[group_id] = group_id
                nodes.append({
                    'id': group_id,
                    'label': group_name,
                    'type': 'group',
                    'group': group_name,
                    'color': {'background': '#fd7e14', 'border': '#b45309'},
                    'shape': 'diamond',
                    'size': 25
                })
                # Connect group to domain
                edges.append({
                    'from': domain_id,
                    'to': group_id,
                    'label': 'Contains',
                    'color': '#848484'
                })
                
                # Connect users to groups
                for member in group.get('Members', []):
                    user_sam = member.get('SamAccountName')
                    if user_sam:
                        user_id = f"user_{user_sam}"
                        if user_id in node_id_map:
                            edges.append({
                                'from': group_id,
                                'to': user_id,
                                'label': 'MemberOf',
                                'color': '#dc3545',
                                'arrows': 'to'
                            })
        
        # Add computers (limit to those with delegation or DCs)
        for computer in self.data.get('Computers', []):
            if computer.get('TrustedForDelegation') or computer.get('TrustedToAuthForDelegation') or computer.get('IsDomainController'):
                comp_id = f"comp_{computer.get('SamAccountName')}"
                node_id_map[comp_id] = comp_id
                color = '#dc3545' if computer.get('IsDomainController') else '#ffc107'
                nodes.append({
                    'id': comp_id,
                    'label': computer.get('SamAccountName', 'N/A').replace('$', ''),
                    'type': 'computer',
                    'group': 'DC' if computer.get('IsDomainController') else 'computer',
                    'color': {'background': color, 'border': '#000'},
                    'shape': 'square',
                    'size': 18
                })
                # Connect computer to domain
                edges.append({
                    'from': domain_id,
                    'to': comp_id,
                    'label': 'Contains',
                    'color': '#848484'
                })
        
        # Add delegation relationships
        for user in high_risk_users:
            if user.get('TrustedForDelegation') or user.get('TrustedToAuthForDelegation'):
                user_id = f"user_{user.get('SamAccountName')}"
                if user_id in node_id_map:
                    # Find computers this user can delegate to
                    for computer in self.data.get('Computers', []):
                        comp_id = f"comp_{computer.get('SamAccountName')}"
                        if comp_id in node_id_map:
                            edges.append({
                                'from': user_id,
                                'to': comp_id,
                                'label': 'DelegatesTo',
                                'color': '#dc3545',
                                'dashes': True,
                                'arrows': 'to',
                                'attackPath': True
                            })
        
        # Detect attack paths (excluding normal/expected configurations)
        attack_paths = []
        
        # Exclude list for normal accounts
        excluded_accounts = ['Administrator', 'krbtgt', 'Guest']
        
        # 1. Find paths to Domain Admins via group membership (exclude default Administrator)
        domain_admins_group_id = f"group_Domain Admins"
        if domain_admins_group_id in node_id_map:
            for user in self.data.get('Users', []):
                user_sam = user.get('SamAccountName', '')
                # Skip default Administrator account unless it has other issues
                if user_sam.lower() == 'administrator':
                    continue
                
                user_id = f"user_{user_sam}"
                if user_id in node_id_map:
                    member_of = self._get_member_of(user)
                    if 'Domain Admins' in member_of:
                        # Check if user is in Protected Users (less risky)
                        is_protected = 'Protected Users' in member_of
                        severity = 'high' if is_protected else 'critical'
                        path = {
                            'type': 'Group Membership',
                            'severity': severity,
                            'description': f"User {user_sam} is a member of Domain Admins" + (" (Protected Users)" if is_protected else " (NOT in Protected Users)"),
                            'path': [user_id, domain_admins_group_id],
                            'steps': [f"User {user_sam} → Domain Admins (Direct Membership)"]
                        }
                        attack_paths.append(path)
        
        # 2. Find Kerberoast attack paths (users with SPNs, exclude krbtgt)
        for user in self.data.get('Users', []):
            user_sam = user.get('SamAccountName', '')
            # Skip krbtgt (it's supposed to have SPNs)
            if user_sam.lower() == 'krbtgt':
                continue
            
            if user.get('SPNs') and len(user.get('SPNs', [])) > 0:
                user_id = f"user_{user_sam}"
                if user_id in node_id_map:
                    # Only flag if user is NOT a service account (heuristic)
                    is_likely_service = (
                        user_sam.lower().startswith('svc_') or 
                        'service' in user_sam.lower() or
                        user.get('Description', '').lower().find('service') >= 0
                    )
                    severity = 'medium' if is_likely_service else 'high'
                    path = {
                        'type': 'Kerberoasting',
                        'severity': severity,
                        'description': f"User {user_sam} has SPNs and is vulnerable to Kerberoasting" + (" (likely service account)" if is_likely_service else ""),
                        'path': [user_id],
                        'steps': [f"User {user_sam} has SPNs: {', '.join(user.get('SPNs', [])[:3])}"]
                    }
                    attack_paths.append(path)
        
        # 3. Find delegation attack paths
        for user in high_risk_users:
            if user.get('TrustedForDelegation') or user.get('TrustedToAuthForDelegation'):
                user_id = f"user_{user.get('SamAccountName')}"
                if user_id in node_id_map:
                    delegation_type = 'Unconstrained' if user.get('TrustedForDelegation') else 'Constrained'
                    path = {
                        'type': f'{delegation_type} Delegation',
                        'severity': 'high',
                        'description': f"User {user.get('SamAccountName')} has {delegation_type.lower()} delegation enabled",
                        'path': [user_id],
                        'steps': [f"User {user.get('SamAccountName')} → Can delegate to services (Privilege Escalation)"]
                    }
                    attack_paths.append(path)
        
        # 4. Find AS-REP roasting paths (exclude normal accounts)
        excluded_accounts = ['Administrator', 'krbtgt', 'Guest']
        for user in self.data.get('Users', []):
            user_sam = user.get('SamAccountName', '')
            if user_sam.lower() in [acc.lower() for acc in excluded_accounts]:
                continue
                
            if user.get('DoesNotRequirePreAuth'):
                user_id = f"user_{user_sam}"
                if user_id in node_id_map:
                    path = {
                        'type': 'AS-REP Roasting',
                        'severity': 'high',
                        'description': f"User {user_sam} does not require pre-authentication (AS-REP roasting)",
                        'path': [user_id],
                        'steps': [f"User {user_sam} → Vulnerable to AS-REP roasting"]
                    }
                    attack_paths.append(path)
        
        # 5. Find unconstrained delegation on non-DC computers (high risk)
        for computer in self.data.get('Computers', []):
            if computer.get('TrustedForDelegation') and not computer.get('IsDomainController'):
                comp_id = f"comp_{computer.get('SamAccountName')}"
                if comp_id in node_id_map:
                    path = {
                        'type': 'Unconstrained Delegation',
                        'severity': 'critical',
                        'description': f"Computer {computer.get('SamAccountName', '').replace('$', '')} has unconstrained delegation (non-DC)",
                        'path': [comp_id],
                        'steps': [f"Computer {computer.get('SamAccountName', '').replace('$', '')} → Unconstrained delegation allows privilege escalation"]
                    }
                    attack_paths.append(path)
        
        # 6. Find paths through nested groups (simplified - direct memberships only for now)
        # Mark edges that are part of attack paths
        attack_path_edge_ids = set()
        for path in attack_paths:
            for i in range(len(path['path']) - 1):
                edge_key = f"{path['path'][i]}_{path['path'][i+1]}"
                attack_path_edge_ids.add(edge_key)
        
        # Mark attack path edges
        for edge in edges:
            edge_key = f"{edge['from']}_{edge['to']}"
            if edge_key in attack_path_edge_ids or edge.get('attackPath'):
                edge['attackPath'] = True
                edge['width'] = 3
                edge['color'] = '#dc3545'
        
        # Prepare user data for node info panel
        user_data_for_js = []
        for user in self.data.get('Users', []):
            user_data_for_js.append({
                'SamAccountName': user.get('SamAccountName'),
                'PasswordLastSet': user.get('PasswordLastSet'),
                'TrustedForDelegation': user.get('TrustedForDelegation'),
                'TrustedToAuthForDelegation': user.get('TrustedToAuthForDelegation'),
                'SPNs': user.get('SPNs', [])
            })
        
        graph_data_js = f"""
        const graphNodes = {json.dumps(nodes, indent=8)};
        const graphEdges = {json.dumps(edges, indent=8)};
        const attackPaths = {json.dumps(attack_paths, indent=8)};
        const userData = {json.dumps(user_data_for_js, indent=8)};
        """
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Active Directory Relationship Graph</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="graph-controls">
                    <button class="graph-filter-btn active" data-filter="all">All</button>
                    <button class="graph-filter-btn" data-filter="high-risk">High Risk</button>
                    <button class="graph-filter-btn" data-filter="attack-paths">Attack Paths</button>
                    <button class="graph-filter-btn" data-filter="user">Users</button>
                    <button class="graph-filter-btn" data-filter="group">Groups</button>
                    <button class="graph-filter-btn" data-filter="computer">Computers</button>
                </div>
                <div style="margin-bottom: 15px;">
                    <strong>Attack Paths Detected: {len(attack_paths)}</strong>
                    <div style="margin-top: 10px; font-size: 12px; color: #6c757d;">
                        {f'<span style="color: #dc3545;">●</span> Critical: {len([p for p in attack_paths if p.get("severity") == "critical"])} | ' if len([p for p in attack_paths if p.get("severity") == "critical"]) > 0 else ''}
                        {f'<span style="color: #ffc107;">●</span> High: {len([p for p in attack_paths if p.get("severity") == "high"])}' if len([p for p in attack_paths if p.get("severity") == "high"]) > 0 else ''}
                    </div>
                </div>
                <div id="graph-container"></div>
                <div id="node-info-panel" class="node-info-panel">
                    <button class="close-btn" onclick="document.getElementById('node-info-panel').classList.remove('visible')">×</button>
                    <h3 id="node-info-title">Node Information</h3>
                    <div id="node-info-content"></div>
                </div>
                <div class="graph-legend">
                    <div class="legend-item">
                        <div class="legend-color" style="background: #dc3545;"></div>
                        <span>High Risk / Domain Controllers</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #ffc107;"></div>
                        <span>Medium Risk / Delegation</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #e74c3c;"></div>
                        <span>Users</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #fd7e14;"></div>
                        <span>Security Groups</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #dc3545; border-radius: 0;"></div>
                        <span>Domain</span>
                    </div>
                </div>
                <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-left: 4px solid #dc3545;">
                    <strong style="color: #dc3545;">Attack Paths Summary</strong>
                    <div id="attack-paths-list" style="margin-top: 10px; max-height: 200px; overflow-y: auto;">
                        {self._format_attack_paths(attack_paths)}
                    </div>
                </div>
                <p style="margin-top: 15px; font-size: 12px; color: #6c757d;">
                    <strong>Instructions:</strong> Click and drag to pan, scroll to zoom, click nodes for details. 
                    Use filter buttons to show specific object types. Red edges indicate high-risk relationships (delegation, admin access).
                    Click "Attack Paths" to highlight all discovered privilege escalation paths.
                </p>
                <script>
                    {graph_data_js}
                </script>
            </div>
        </div>
        """
    
    def _format_attack_paths(self, attack_paths: List[Dict[str, Any]]) -> str:
        """Format attack paths for display"""
        if not attack_paths:
            return '<p style="color: #6c757d;">No attack paths detected.</p>'
        
        html = '<div style="font-size: 12px;">'
        for i, path in enumerate(attack_paths[:20]):  # Limit to 20 for performance
            severity_color = '#dc3545' if path.get('severity') == 'critical' else '#ffc107'
            html += f'''
            <div style="margin-bottom: 10px; padding: 8px; background: white; border-left: 3px solid {severity_color};">
                <strong style="color: {severity_color};">{path.get('type', 'Unknown')}</strong>
                <div style="margin-top: 4px; color: #495057;">{path.get('description', '')}</div>
                <div style="margin-top: 4px; font-size: 11px; color: #6c757d;">
                    {' → '.join(path.get('steps', []))}
                </div>
            </div>
            '''
        if len(attack_paths) > 20:
            html += f'<p style="color: #6c757d; margin-top: 10px;">... and {len(attack_paths) - 20} more attack paths</p>'
        html += '</div>'
        return html
    
    def generate_domain_info_table(self) -> str:
        """Generate domain and forest information"""
        domain_info = self.data.get('DomainInfo')
        forest_info = self.data.get('ForestInfo')
        
        if not domain_info and not forest_info:
            return ""
        
        rows = []
        if domain_info:
            rows.append(f"<tr><td><strong>Domain Name</strong></td><td>{domain_info.get('Name', 'N/A')}</td></tr>")
            rows.append(f"<tr><td><strong>NetBIOS Name</strong></td><td>{domain_info.get('NetBIOSName', 'N/A')}</td></tr>")
            rows.append(f"<tr><td><strong>Domain Mode</strong></td><td>{domain_info.get('DomainMode', 'N/A')}</td></tr>")
            rows.append(f"<tr><td><strong>Domain SID</strong></td><td>{domain_info.get('DomainSID', 'N/A')}</td></tr>")
            rows.append(f"<tr><td><strong>Created</strong></td><td>{domain_info.get('Created', 'N/A')}</td></tr>")
        
        if forest_info:
            rows.append(f"<tr><td><strong>Forest Name</strong></td><td>{forest_info.get('Name', 'N/A')}</td></tr>")
            rows.append(f"<tr><td><strong>Forest Mode</strong></td><td>{forest_info.get('ForestMode', 'N/A')}</td></tr>")
            rows.append(f"<tr><td><strong>Schema Master</strong></td><td>{forest_info.get('SchemaMaster', 'N/A')}</td></tr>")
            rows.append(f"<tr><td><strong>Domain Naming Master</strong></td><td>{forest_info.get('DomainNamingMaster', 'N/A')}</td></tr>")
            rows.append(f"<tr><td><strong>Root Domain</strong></td><td>{forest_info.get('RootDomain', 'N/A')}</td></tr>")
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Domain & Forest Information</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <table class="data-table">
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_ldap_smb_policy_table(self) -> str:
        """Generate LDAP and SMB signing policy information"""
        ldap_policy = self.data.get('LDAPPolicy')
        smb_policy = self.data.get('SMBPolicy')
        
        if not ldap_policy and not smb_policy:
            return ""
        
        rows = []
        if ldap_policy:
            ldap_signing = ldap_policy.get('LDAPSigningRequired')
            ldap_badge = '<span class="badge badge-green">Required</span>' if ldap_signing else '<span class="badge badge-red">Not Required</span>' if ldap_signing is False else '<span class="badge badge-gray">Unknown</span>'
            rows.append(f"<tr><td><strong>LDAP Signing Required</strong></td><td>{ldap_badge}</td></tr>")
        
        if smb_policy:
            smb_client = smb_policy.get('ClientSigningRequired')
            smb_server = smb_policy.get('ServerSigningRequired')
            client_badge = '<span class="badge badge-green">Required</span>' if smb_client else '<span class="badge badge-red">Not Required</span>' if smb_client is False else '<span class="badge badge-gray">Unknown</span>'
            server_badge = '<span class="badge badge-green">Required</span>' if smb_server else '<span class="badge badge-red">Not Required</span>' if smb_server is False else '<span class="badge badge-gray">Unknown</span>'
            rows.append(f"<tr><td><strong>SMB Client Signing</strong></td><td>{client_badge}</td></tr>")
            rows.append(f"<tr><td><strong>SMB Server Signing</strong></td><td>{server_badge}</td></tr>")
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> LDAP & SMB Signing Policy</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <table class="data-table">
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
                <div class="alert alert-warning" style="margin-top: 15px;">
                    <strong>Security Note:</strong> LDAP and SMB signing should be required to prevent man-in-the-middle attacks.
                </div>
            </div>
        </div>
        """
    
    def generate_fine_grained_password_policies_table(self) -> str:
        """Generate fine-grained password policies table"""
        policies = self.data.get('FineGrainedPasswordPolicies', [])
        
        if not policies:
            return ""
        
        rows = []
        for policy in policies:
            applies_to = ', '.join(policy.get('AppliesTo', [])) if policy.get('AppliesTo') else 'N/A'
            rows.append(f"""
                <tr>
                    <td>{policy.get('Name', 'N/A')}</td>
                    <td>{policy.get('MinPasswordLength', 'N/A')}</td>
                    <td>{policy.get('PasswordHistoryCount', 'N/A')}</td>
                    <td>{policy.get('LockoutThreshold', 'N/A')}</td>
                    <td>{'<span class="badge badge-green">Yes</span>' if policy.get('ComplexityEnabled') else '<span class="badge badge-red">No</span>'}</td>
                    <td>{applies_to}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Fine-Grained Password Policies ({len(policies)})</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Policy Name</th>
                                <th>Min Length</th>
                                <th>History</th>
                                <th>Lockout Threshold</th>
                                <th>Complexity</th>
                                <th>Applies To</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
    
    def generate_certificate_authorities_table(self) -> str:
        """Generate certificate authorities table"""
        cas = self.data.get('CertificateAuthorities', [])
        
        if not cas:
            return ""
        
        rows = []
        for ca in cas:
            expired_badge = '<span class="badge badge-red">Expired</span>' if ca.get('IsExpired') else '<span class="badge badge-green">Valid</span>'
            rows.append(f"""
                <tr>
                    <td>{ca.get('Name', 'N/A')}</td>
                    <td>{ca.get('Thumbprint', 'N/A')[:20]}...</td>
                    <td>{ca.get('NotBefore', 'N/A')}</td>
                    <td>{ca.get('NotAfter', 'N/A')}</td>
                    <td>{expired_badge}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Certificate Authorities ({len(cas)})</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Thumbprint</th>
                                <th>Valid From</th>
                                <th>Valid To</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
    
    def generate_certificate_templates_table(self) -> str:
        """Generate certificate templates table"""
        templates = self.data.get('CertificateTemplates', [])
        
        if not templates:
            return ""
        
        rows = []
        for template in templates:
            auto_enroll_badge = '<span class="badge badge-yellow">Auto-Enroll</span>' if template.get('AutoEnrollment') else '<span class="badge badge-gray">Manual</span>'
            approval_badge = '<span class="badge badge-green">Required</span>' if template.get('RequiresManagerApproval') else '<span class="badge badge-red">Not Required</span>'
            rows.append(f"""
                <tr>
                    <td>{template.get('Name', 'N/A')}</td>
                    <td>{template.get('DisplayName', 'N/A')}</td>
                    <td>{auto_enroll_badge}</td>
                    <td>{approval_badge}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Certificate Templates ({len(templates)})</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Display Name</th>
                                <th>Enrollment</th>
                                <th>Manager Approval</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
    
    def generate_empty_groups_table(self) -> str:
        """Generate empty groups table"""
        groups = self.data.get('EmptyGroups', [])
        
        if not groups:
            return ""
        
        rows = []
        for group in groups[:50]:  # Limit to 50 for display
            rows.append(f"""
                <tr>
                    <td>{group.get('Name', 'N/A')}</td>
                    <td>{group.get('GroupScope', 'N/A')}</td>
                    <td>{group.get('GroupCategory', 'N/A')}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Empty Security Groups ({len(groups)})</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-info">
                    <strong>Note:</strong> Empty groups may indicate unused groups that should be reviewed for removal.
                </div>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Group Name</th>
                                <th>Scope</th>
                                <th>Category</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
                {f'<p style="margin-top: 10px; color: #6c757d;">Showing first 50 of {len(groups)} empty groups</p>' if len(groups) > 50 else ''}
            </div>
        </div>
        """
    
    def generate_large_groups_table(self) -> str:
        """Generate large groups table"""
        groups = self.data.get('LargeGroups', [])
        
        if not groups:
            return ""
        
        rows = []
        for group in sorted(groups, key=lambda x: x.get('MemberCount', 0), reverse=True):
            rows.append(f"""
                <tr>
                    <td>{group.get('Name', 'N/A')}</td>
                    <td>{group.get('MemberCount', 0):,}</td>
                    <td>{group.get('GroupScope', 'N/A')}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Large Security Groups ({len(groups)})</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-warning">
                    <strong>Security Note:</strong> Groups with >1000 members may indicate over-privileged access. Review for least privilege.
                </div>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Group Name</th>
                                <th>Member Count</th>
                                <th>Scope</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
    
    def generate_suspicious_accounts_table(self) -> str:
        """Generate suspicious accounts table"""
        accounts = self.data.get('SuspiciousAccounts', [])
        
        if not accounts:
            return ""
        
        rows = []
        for account in accounts:
            reasons = '<br>'.join(account.get('Reasons', []))
            member_of_list = account.get('MemberOf') or []
            member_of = ', '.join(member_of_list[:3]) if member_of_list else 'None'
            if len(member_of_list) > 3:
                member_of += f" (+{len(member_of_list) - 3} more)"
            rows.append(f"""
                <tr>
                    <td>{account.get('SamAccountName', 'N/A')}</td>
                    <td>{account.get('DisplayName', 'N/A')}</td>
                    <td>{'<span class="badge badge-green">Enabled</span>' if account.get('Enabled') else '<span class="badge badge-red">Disabled</span>'}</td>
                    <td>{reasons}</td>
                    <td>{member_of}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Suspicious Accounts ({len(accounts)})</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-warning">
                    <strong>Security Alert:</strong> These accounts have security issues that require immediate review.
                </div>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Account</th>
                                <th>Display Name</th>
                                <th>Status</th>
                                <th>Security Issues</th>
                                <th>Member Of</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
    
    def generate_failed_logons_table(self) -> str:
        """Generate failed logon attempts table"""
        failed_logons = self.data.get('FailedLogons', [])
        
        if not failed_logons:
            return ""
        
        # Group by account
        account_counts = {}
        for logon in failed_logons:
            account = f"{logon.get('AccountDomain', '')}\\{logon.get('AccountName', 'N/A')}"
            account_counts[account] = account_counts.get(account, 0) + 1
        
        top_accounts = sorted(account_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        rows = []
        for logon in failed_logons[:50]:  # Limit to 50 for display
            account = f"{logon.get('AccountDomain', '')}\\{logon.get('AccountName', 'N/A')}"
            rows.append(f"""
                <tr>
                    <td>{logon.get('TimeCreated', 'N/A')}</td>
                    <td>{account}</td>
                    <td>{logon.get('IPAddress', 'N/A')}</td>
                    <td>{logon.get('WorkstationName', 'N/A')}</td>
                    <td>{logon.get('FailureReason', 'N/A')}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Failed Logon Attempts ({len(failed_logons)})</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                {f'''
                <div style="margin-bottom: 20px;">
                    <h3 style="font-size: 14px; margin-bottom: 10px; color: #495057;">Top Accounts with Failed Logons</h3>
                    <table class="data-table" style="margin-bottom: 20px;">
                        <thead>
                            <tr>
                                <th>Account</th>
                                <th>Failed Attempts</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join([f'<tr><td>{acc}</td><td>{count}</td></tr>' for acc, count in top_accounts])}
                        </tbody>
                    </table>
                </div>
                ''' if top_accounts else ''}
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Account</th>
                                <th>IP Address</th>
                                <th>Workstation</th>
                                <th>Failure Reason</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
                {f'<p style="margin-top: 10px; color: #6c757d;">Showing first 50 of {len(failed_logons)} failed logon attempts</p>' if len(failed_logons) > 50 else ''}
            </div>
        </div>
        """
    
    def generate_nested_groups_table(self) -> str:
        """Generate nested groups table"""
        groups = self.data.get('NestedGroups', [])
        
        if not groups:
            return ""
        
        rows = []
        for group in sorted(groups, key=lambda x: x.get('NestingDepth', 0), reverse=True):
            rows.append(f"""
                <tr>
                    <td>{group.get('GroupName', 'N/A')}</td>
                    <td>{group.get('NestingDepth', 0)}</td>
                    <td>{'<span class="badge badge-red">High</span>' if group.get('NestingDepth', 0) >= 7 else '<span class="badge badge-yellow">Medium</span>'}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Deeply Nested Groups ({len(groups)})</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-warning">
                    <strong>Security Note:</strong> Groups with deep nesting (>=5 levels) can be difficult to manage and may indicate over-complex permission structures.
                </div>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Group Name</th>
                                <th>Nesting Depth</th>
                                <th>Risk Level</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
    
    def generate_outdated_computers_table(self) -> str:
        """Generate outdated computers table"""
        computers = self.data.get('OutdatedComputers', [])
        
        if not computers:
            return ""
        
        rows = []
        for comp in computers:
            enabled_badge = '<span class="badge badge-green">Enabled</span>' if comp.get('Enabled') else '<span class="badge badge-red">Disabled</span>'
            rows.append(f"""
                <tr>
                    <td>{comp.get('SamAccountName', 'N/A').replace('$', '')}</td>
                    <td>{comp.get('OperatingSystem', 'N/A')}</td>
                    <td>{comp.get('OperatingSystemVersion', 'N/A')}</td>
                    <td><span class="badge badge-red">{comp.get('Reason', 'N/A')}</span></td>
                    <td>{enabled_badge}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Outdated Computers ({len(computers)})</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-warning">
                    <strong>Security Alert:</strong> Outdated operating systems are no longer supported and may have unpatched vulnerabilities.
                </div>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Computer Name</th>
                                <th>Operating System</th>
                                <th>Version</th>
                                <th>Reason</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
    
    def generate_service_account_issues_table(self) -> str:
        """Generate service account issues table"""
        issues = self.data.get('ServiceAccountIssues', [])
        
        if not issues:
            return ""
        
        rows = []
        for issue in issues:
            issues_list = '<br>'.join([f'• {i}' for i in issue.get('Issues', [])])
            rows.append(f"""
                <tr>
                    <td>{issue.get('SamAccountName', 'N/A')}</td>
                    <td>{issue.get('DisplayName', 'N/A')}</td>
                    <td>{issues_list}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Service Account Security Issues ({len(issues)})</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-warning">
                    <strong>Security Note:</strong> Service accounts should use gMSA or have PasswordNeverExpires set. They should not be in privileged groups.
                </div>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Account</th>
                                <th>Display Name</th>
                                <th>Issues</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
    
    def generate_gpo_issues_table(self) -> str:
        """Generate GPO issues table"""
        issues = self.data.get('GPOIssues', [])
        
        if not issues:
            return ""
        
        rows = []
        for issue in issues:
            severity_badge = '<span class="badge badge-red">High</span>' if issue.get('Severity') == 'high' else '<span class="badge badge-yellow">Medium</span>'
            rows.append(f"""
                <tr>
                    <td>{issue.get('GPO', 'N/A')}</td>
                    <td>{issue.get('Issue', 'N/A')}</td>
                    <td>{severity_badge}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> GPO Issues ({len(issues)})</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>GPO Name</th>
                                <th>Issue</th>
                                <th>Severity</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
    
    def generate_kerberos_policy_table(self) -> str:
        """Generate Kerberos policy table"""
        policy = self.data.get('KerberosPolicy')
        
        if not policy:
            return ""
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Kerberos Policy</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <table class="data-table">
                    <tbody>
                        <tr><td><strong>Max Clock Skew</strong></td><td>{policy.get('MaxClockSkew', 'N/A')} minutes</td></tr>
                        <tr><td><strong>Max Service Age</strong></td><td>{policy.get('MaxServiceAge', 'N/A')} minutes</td></tr>
                        <tr><td><strong>Max Ticket Age</strong></td><td>{policy.get('MaxTicketAge', 'N/A')} hours</td></tr>
                        <tr><td><strong>Max Renew Age</strong></td><td>{policy.get('MaxRenewAge', 'N/A')} days</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_anonymous_access_table(self) -> str:
        """Generate anonymous access settings table"""
        anon = self.data.get('AnonymousAccess')
        
        if not anon:
            return ""
        
        anon_enabled = anon.get('AnonymousAccessEnabled')
        anon_badge = '<span class="badge badge-red">Enabled</span>' if anon_enabled else '<span class="badge badge-green">Restricted</span>' if anon_enabled is False else '<span class="badge badge-gray">Unknown</span>'
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Anonymous Access Settings</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <table class="data-table">
                    <tbody>
                        <tr><td><strong>Anonymous Access</strong></td><td>{anon_badge}</td></tr>
                        <tr><td><strong>RestrictAnonymous Value</strong></td><td>{anon.get('RestrictAnonymous', 'N/A')}</td></tr>
                    </tbody>
                </table>
                <div class="alert alert-warning" style="margin-top: 15px;">
                    <strong>Security Note:</strong> Anonymous access should be restricted to prevent information disclosure.
                </div>
            </div>
        </div>
        """
    
    def generate_smbv1_usage_table(self) -> str:
        """Generate SMBv1 usage table"""
        usage = self.data.get('SMBv1Usage', [])
        
        if not usage:
            return ""
        
        rows = []
        for item in usage:
            client_badge = '<span class="badge badge-red">Enabled</span>' if item.get('SMBv1ClientEnabled') else '<span class="badge badge-green">Disabled</span>'
            server_badge = '<span class="badge badge-red">Enabled</span>' if item.get('SMBv1ServerEnabled') else '<span class="badge badge-green">Disabled</span>'
            rows.append(f"""
                <tr>
                    <td>{item.get('ComputerName', 'N/A')}</td>
                    <td>{client_badge}</td>
                    <td>{server_badge}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> SMBv1 Usage ({len(usage)})</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-warning">
                    <strong>Security Alert:</strong> SMBv1 is vulnerable and should be disabled. It was used in WannaCry and other ransomware attacks.
                </div>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Computer</th>
                                <th>SMBv1 Client</th>
                                <th>SMBv1 Server</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
    
    def generate_rdp_winrm_table(self) -> str:
        """Generate RDP and WinRM settings table"""
        rdp = self.data.get('RDPEnabled', [])
        winrm = self.data.get('WinRMEnabled', [])
        
        if not rdp and not winrm:
            return ""
        
        rows = []
        all_computers = set()
        for item in rdp:
            all_computers.add(item.get('ComputerName', 'N/A'))
        for item in winrm:
            all_computers.add(item.get('ComputerName', 'N/A'))
        
        for comp in all_computers:
            rdp_item = next((x for x in rdp if x.get('ComputerName') == comp), None)
            winrm_item = next((x for x in winrm if x.get('ComputerName') == comp), None)
            
            rdp_badge = '<span class="badge badge-yellow">Enabled</span>' if rdp_item and rdp_item.get('Enabled') else '<span class="badge badge-gray">Unknown</span>'
            winrm_badge = '<span class="badge badge-yellow">Enabled</span>' if winrm_item and winrm_item.get('Enabled') else '<span class="badge badge-gray">Unknown</span>'
            
            rows.append(f"""
                <tr>
                    <td>{comp}</td>
                    <td>{rdp_badge}</td>
                    <td>{winrm_badge}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Remote Access (RDP/WinRM)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-info">
                    <strong>Note:</strong> Remote access should be properly secured with strong authentication and network restrictions.
                </div>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Computer</th>
                                <th>RDP</th>
                                <th>WinRM</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
    
    def generate_event_log_settings_table(self) -> str:
        """Generate event log settings table"""
        settings = self.data.get('EventLogSettings')
        
        if not settings:
            return ""
        
        retention_map = {
            'Circular': 'Overwrites old events',
            'Retain': 'Retains events',
            'AutoBackup': 'Auto-backup when full'
        }
        retention = retention_map.get(settings.get('SecurityLogRetention', ''), settings.get('SecurityLogRetention', 'N/A'))
        max_size_bytes = settings.get('SecurityLogMaxSize', 0) or 0
        max_size_mb = max_size_bytes / (1024 * 1024) if max_size_bytes > 0 else 0
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Event Log Settings</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <table class="data-table">
                    <tbody>
                        <tr><td><strong>Security Log Max Size</strong></td><td>{max_size_mb:.2f} MB</td></tr>
                        <tr><td><strong>Security Log Retention</strong></td><td>{retention}</td></tr>
                        <tr><td><strong>Security Log Enabled</strong></td><td>{'<span class="badge badge-green">Yes</span>' if settings.get('SecurityLogEnabled') else '<span class="badge badge-red">No</span>'}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_gpo_settings_table(self) -> str:
        """Generate GPO settings table"""
        gpos = self.data.get('GPOSettings', [])
        
        if not gpos:
            return ""
        
        rows = []
        for gpo in gpos[:50]:  # Limit to 50 for display
            enabled_badge = '<span class="badge badge-green">Enabled</span>' if gpo.get('Enabled') else '<span class="badge badge-yellow">Disabled</span>'
            rows.append(f"""
                <tr>
                    <td>{gpo.get('DisplayName', 'N/A')}</td>
                    <td>{gpo.get('GUID', 'N/A')}</td>
                    <td>{gpo.get('Created', 'N/A')}</td>
                    <td>{gpo.get('Modified', 'N/A')}</td>
                    <td>{enabled_badge}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Group Policy Objects ({len(gpos)})</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>GPO Name</th>
                                <th>GUID</th>
                                <th>Created</th>
                                <th>Modified</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
                {f'<p style="margin-top: 10px; color: #6c757d;">Showing first 50 of {len(gpos)} GPOs</p>' if len(gpos) > 50 else ''}
            </div>
        </div>
        """
    
    def generate_computer_security_status_table(self) -> str:
        """Generate computer security status table (AV, BitLocker, Firewall)"""
        security_status = self.data.get('ComputerSecurityStatus', [])
        total_computers = len(self.data.get('Computers', []))
        enabled_computers = len([c for c in self.data.get('Computers', []) if c.get('Enabled')])
        
        if not security_status or len(security_status) == 0:
            return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Computer Security Status (0 checked)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-warning">
                    <strong>No Computer Security Data Collected</strong>
                    <p style="margin-top: 10px;">Computer security status (Antivirus, BitLocker, Firewall, Windows Update) was not collected.</p>
                    <p><strong>Possible reasons:</strong></p>
                    <ul style="margin-top: 10px; margin-left: 20px;">
                        <li>The PowerShell script was run with <code>-SkipComputerSecurityChecks</code> parameter</li>
                        <li>No enabled computers found in AD (Total: {total_computers}, Enabled: {enabled_computers})</li>
                        <li>All computers are offline or unreachable</li>
                        <li>Insufficient permissions to query remote computers via WMI/CIM</li>
                        <li>Firewall rules blocking remote management (WMI/CIM ports)</li>
                    </ul>
                    <p style="margin-top: 15px;"><strong>To collect this data:</strong></p>
                    <ol style="margin-top: 5px; margin-left: 20px;">
                        <li>Run the PowerShell script <strong>without</strong> <code>-SkipComputerSecurityChecks</code>:
                            <pre style="background: #f8f9fa; padding: 10px; margin-top: 5px; border: 1px solid #dee2e6;">.\Get-ADAudit.ps1</pre>
                        </li>
                        <li>Ensure you have local administrator permissions on target computers</li>
                        <li>Verify computers are online and reachable</li>
                        <li>Check that Windows Firewall allows WMI/CIM connections (ports 135, 445, 5985, 5986)</li>
                    </ol>
                </div>
            </div>
        </div>
        """
        
        rows = []
        for comp in security_status:
            av = comp.get('Antivirus', {})
            bitlocker = comp.get('BitLocker', {})
            firewall = comp.get('Firewall', {})
            updates = comp.get('WindowsUpdate', {})
            
            av_badge = '<span class="badge badge-green">Installed</span>' if av.get('Installed') else '<span class="badge badge-red">Not Found</span>' if av.get('Online') else '<span class="badge badge-gray">Offline</span>'
            if av.get('Installed') and not av.get('RealTimeProtectionEnabled'):
                av_badge = '<span class="badge badge-yellow">No Real-time</span>'
            
            bitlocker_badge = '<span class="badge badge-green">Enabled</span>' if bitlocker.get('Enabled') else '<span class="badge badge-yellow">Not Enabled</span>' if bitlocker.get('Online') else '<span class="badge badge-gray">Offline</span>'
            
            firewall_badge = '<span class="badge badge-green">Enabled</span>' if firewall.get('Enabled') else '<span class="badge badge-red">Disabled</span>' if firewall.get('Online') else '<span class="badge badge-gray">Offline</span>'
            
            updates_badge = '<span class="badge badge-green">Running</span>' if updates.get('AutoUpdateEnabled') else '<span class="badge badge-yellow">Stopped</span>' if updates.get('Online') else '<span class="badge badge-gray">Offline</span>'
            
            rows.append(f"""
                <tr>
                    <td>{comp.get('ComputerName', 'N/A')}</td>
                    <td>{av_badge}</td>
                    <td>{av.get('ProductName', 'N/A') if av.get('Installed') else 'N/A'}</td>
                    <td>{bitlocker_badge}</td>
                    <td>{firewall_badge}</td>
                    <td>{updates_badge}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2><span class="section-icon">▸</span> Computer Security Status ({len(security_status)} computers)</h2>
                <span class="section-toggle">▼</span>
            </div>
            <div class="section-content">
                <div class="alert alert-info">
                    <strong>Note:</strong> Security status is gathered for online computers only. Some computers may be offline or inaccessible.
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Computer</th>
                            <th>Antivirus</th>
                            <th>AV Product</th>
                            <th>BitLocker</th>
                            <th>Firewall</th>
                            <th>Windows Update</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_recommendations(self) -> str:
        """Generate remediation recommendations"""
        recommendations = []
        
        users_with_spns = len([u for u in self.data.get('Users', []) if u.get('SPNs') and len(u.get('SPNs', [])) > 0])
        if users_with_spns > 0:
            recommendations.append(f"<li><strong>Kerberoasting:</strong> {users_with_spns} user accounts have SPNs. Move SPNs to managed service accounts (gMSA) or use Group Managed Service Accounts.</li>")
        
        users_with_delegation = len([u for u in self.data.get('Users', []) if u.get('TrustedForDelegation') or u.get('TrustedToAuthForDelegation')])
        if users_with_delegation > 0:
            recommendations.append(f"<li><strong>Delegation:</strong> {users_with_delegation} user accounts have delegation enabled. Review and disable unnecessary delegation. Prefer constrained delegation over unconstrained.</li>")
        
        computers_with_delegation = len([c for c in self.data.get('Computers', []) 
                                        if (c.get('TrustedForDelegation') or c.get('TrustedToAuthForDelegation') or 
                                            (c.get('ConstrainedDelegation') and len(c.get('ConstrainedDelegation', [])) > 0))
                                        and not c.get('IsDomainController', False)])
        if computers_with_delegation > 0:
            recommendations.append(f"<li><strong>Computer Delegation:</strong> {computers_with_delegation} non-DC computers have delegation. This is a high-risk configuration that should be reviewed.</li>")
        
        weak_encryption = len([u for u in self.data.get('Users', [])
                              if any(enc in ['DES', 'RC4'] for enc in u.get('EncryptionTypes', []))
                              or u.get('UseDESKeyOnly', False)])
        if weak_encryption > 0:
            recommendations.append(f"<li><strong>Weak Encryption:</strong> {weak_encryption} accounts support DES or RC4. Disable these encryption types via Group Policy and update account settings.</li>")
        
        domain_admins = [u for u in self.data.get('Users', []) if 'Domain Admins' in self._get_member_of(u)]
        unprotected_admins = [u for u in domain_admins if 'Protected Users' not in self._get_member_of(u)]
        if len(unprotected_admins) > 0:
            recommendations.append(f"<li><strong>Privileged Accounts:</strong> {len(unprotected_admins)} Domain/Enterprise Admins are not in Protected Users group. Add them to reduce credential theft risk.</li>")
        
        inactive = len([u for u in self.data.get('Users', []) if u.get('DaysSinceLastLogon') and u.get('DaysSinceLastLogon') > 90])
        if inactive > 0:
            recommendations.append(f"<li><strong>Inactive Accounts:</strong> {inactive} accounts haven't logged in for 90+ days. Review and disable/remove if no longer needed.</li>")
        
        old_passwords = len([u for u in self.data.get('Users', []) if u.get('DaysSincePasswordChange') and u.get('DaysSincePasswordChange') > 365])
        if old_passwords > 0:
            recommendations.append(f"<li><strong>Password Age:</strong> {old_passwords} accounts have passwords older than 365 days. Enforce password rotation policies.</li>")
        
        krbtgt = self.data.get('KrbtgtInfo')
        if krbtgt and krbtgt.get('DaysSincePasswordChange', 0) > 180:
            recommendations.append(f"<li><strong>krbtgt Password:</strong> krbtgt password is {krbtgt.get('DaysSincePasswordChange')} days old. Rotate krbtgt password (requires domain controller maintenance).</li>")
        
        # Password policy recommendations
        policy = self.data.get('PasswordPolicy')
        if policy:
            if policy.get('MinPasswordLength', 0) < 14:
                recommendations.append(f"<li><strong>Password Policy:</strong> Minimum password length is {policy.get('MinPasswordLength')}. Consider increasing to 14+ characters for better security.</li>")
            if policy.get('ReversibleEncryptionEnabled'):
                recommendations.append(f"<li><strong>Password Policy:</strong> Reversible encryption is enabled. This is a critical security risk - disable immediately.</li>")
            if not policy.get('ComplexityEnabled'):
                recommendations.append(f"<li><strong>Password Policy:</strong> Password complexity is disabled. Enable it to require mixed case, numbers, and special characters.</li>")
            if not policy.get('LockoutThreshold') or policy.get('LockoutThreshold') == 0:
                recommendations.append(f"<li><strong>Password Policy:</strong> Account lockout threshold is not set. Configure lockout after 3-10 failed attempts.</li>")
        
        # Trust relationship recommendations
        trusts = self.data.get('TrustRelationships', [])
        for trust in trusts:
            if not trust.get('SIDFilteringForestAware'):
                recommendations.append(f"<li><strong>Trust Relationship:</strong> SID filtering is disabled for trust '{trust.get('Name')}'. Enable SID filtering to prevent SID history attacks.</li>")
            if not trust.get('SelectiveAuthentication'):
                recommendations.append(f"<li><strong>Trust Relationship:</strong> Selective authentication is disabled for trust '{trust.get('Name')}'. Enable it to restrict cross-trust access.</li>")
        
        # Computer security recommendations
        security_status = self.data.get('ComputerSecurityStatus', [])
        computers_without_av = [c for c in security_status if c.get('Antivirus', {}).get('Online') and not c.get('Antivirus', {}).get('Installed')]
        if computers_without_av:
            recommendations.append(f"<li><strong>Antivirus:</strong> {len(computers_without_av)} online computers do not have antivirus installed. Install and maintain antivirus on all systems.</li>")
        
        computers_without_bitlocker = [c for c in security_status if c.get('BitLocker', {}).get('Online') and not c.get('BitLocker', {}).get('Enabled')]
        if computers_without_bitlocker:
            recommendations.append(f"<li><strong>BitLocker:</strong> {len(computers_without_bitlocker)} online computers do not have BitLocker enabled. Enable full disk encryption on all systems.</li>")
        
        computers_without_firewall = [c for c in security_status if c.get('Firewall', {}).get('Online') and not c.get('Firewall', {}).get('Enabled')]
        if computers_without_firewall:
            recommendations.append(f"<li><strong>Firewall:</strong> {len(computers_without_firewall)} online computers have firewall disabled. Enable Windows Firewall on all systems.</li>")
        
        # LDAP/SMB signing recommendations
        ldap_policy = self.data.get('LDAPPolicy')
        if ldap_policy and not ldap_policy.get('LDAPSigningRequired'):
            recommendations.append("<li><strong>LDAP Signing:</strong> LDAP signing is not required. Enable LDAP signing to prevent man-in-the-middle attacks.</li>")
        
        smb_policy = self.data.get('SMBPolicy')
        if smb_policy:
            if not smb_policy.get('ClientSigningRequired'):
                recommendations.append("<li><strong>SMB Signing:</strong> SMB client signing is not required. Enable SMB signing to prevent relay attacks.</li>")
            if not smb_policy.get('ServerSigningRequired'):
                recommendations.append("<li><strong>SMB Signing:</strong> SMB server signing is not required. Enable SMB signing to prevent relay attacks.</li>")
        
        # Domain/Forest mode recommendations
        domain_info = self.data.get('DomainInfo')
        if domain_info:
            domain_mode = domain_info.get('DomainMode', '')
            if domain_mode and '2008' in domain_mode:
                recommendations.append(f"<li><strong>Domain Mode:</strong> Domain is running in {domain_mode} mode. Consider upgrading to Windows Server 2016 or later for enhanced security features.</li>")
        
        forest_info = self.data.get('ForestInfo')
        if forest_info:
            forest_mode = forest_info.get('ForestMode', '')
            if forest_mode and '2008' in forest_mode:
                recommendations.append(f"<li><strong>Forest Mode:</strong> Forest is running in {forest_mode} mode. Consider upgrading to Windows Server 2016 or later for enhanced security features.</li>")
        
        # Suspicious accounts
        suspicious = self.data.get('SuspiciousAccounts', [])
        if suspicious:
            recommendations.append(f"<li><strong>Suspicious Accounts:</strong> {len(suspicious)} accounts have security issues. Review and remediate immediately.</li>")
        
        # Failed logons
        failed_logons = self.data.get('FailedLogons', [])
        if failed_logons and len(failed_logons) > 50:
            recommendations.append(f"<li><strong>Failed Logons:</strong> {len(failed_logons)} failed logon attempts detected. Investigate potential brute-force attacks.</li>")
        
        # Empty groups
        empty_groups = self.data.get('EmptyGroups', [])
        if empty_groups and len(empty_groups) > 10:
            recommendations.append(f"<li><strong>Empty Groups:</strong> {len(empty_groups)} empty groups found. Review and remove unused groups to reduce attack surface.</li>")
        
        # Large groups
        large_groups = self.data.get('LargeGroups', [])
        if large_groups:
            recommendations.append(f"<li><strong>Large Groups:</strong> {len(large_groups)} groups have >1000 members. Review for over-privileged access and implement least privilege.</li>")
        
        # Certificate templates
        cert_templates = self.data.get('CertificateTemplates', [])
        dangerous_templates = [t for t in cert_templates if not t.get('RequiresManagerApproval') and t.get('AutoEnrollment')]
        if dangerous_templates:
            recommendations.append(f"<li><strong>Certificate Templates:</strong> {len(dangerous_templates)} certificate templates allow auto-enrollment without manager approval. This is a security risk.</li>")
        
        # Expired certificates
        cas = self.data.get('CertificateAuthorities', [])
        expired_cas = [ca for ca in cas if ca.get('IsExpired')]
        if expired_cas:
            recommendations.append(f"<li><strong>Certificates:</strong> {len(expired_cas)} certificate authorities are expired. Renew or remove expired certificates.</li>")
        
        if not recommendations:
            recommendations.append("<li>No critical issues detected. Continue monitoring and maintain security best practices.</li>")
        
        return f"<ul>{''.join(recommendations)}</ul>"
    
    def generate_html(self) -> str:
        """Generate complete HTML report"""
        self.calculate_risk_scores()
        overall_score, risk_class, risk_label = self.get_overall_risk_score()
        
        stats = self.data.get('Statistics', {})
        
        # Generate all sections
        sections = [
            self.generate_graph_visualization(),
            self.generate_domain_info_table(),
            self.generate_password_policy_table(),
            self.generate_ldap_smb_policy_table(),
            self.generate_fine_grained_password_policies_table(),
            self.generate_kerberoast_table(),
            self.generate_delegation_table(),
            self.generate_encryption_table(),
            self.generate_privileged_accounts_table(),
            self.generate_suspicious_accounts_table(),
            self.generate_inactive_accounts_table(),
            self.generate_krbtgt_info(),
            self.generate_ntlm_info(),
            self.generate_failed_logons_table(),
            self.generate_domain_controllers_table(),
            self.generate_trust_relationships_table(),
            self.generate_security_groups_table(),
            self.generate_empty_groups_table(),
            self.generate_large_groups_table(),
            self.generate_certificate_authorities_table(),
            self.generate_certificate_templates_table(),
            self.generate_gpo_settings_table(),
            self.generate_gpo_issues_table(),
            self.generate_kerberos_policy_table(),
            self.generate_anonymous_access_table(),
            self.generate_nested_groups_table(),
            self.generate_outdated_computers_table(),
            self.generate_service_account_issues_table(),
            self.generate_smbv1_usage_table(),
            self.generate_rdp_winrm_table(),
            self.generate_event_log_settings_table(),
            self.generate_computer_security_status_table(),
            self.generate_user_table(),
            self.generate_computer_table(),
            self.generate_service_accounts_table()
        ]
        
        sections_html = '\n'.join([s for s in sections if s])
        
        return HTML_TEMPLATE.format(
            domain=self.data.get('Domain', 'Unknown'),
            timestamp=self.data.get('Timestamp', datetime.now().isoformat()),
            overall_risk_score=overall_score,
            overall_risk_class=risk_class,
            overall_risk_label=risk_label,
            total_users=stats.get('TotalUsers', 0),
            total_computers=stats.get('TotalComputers', 0),
            kerberoast_targets=stats.get('UsersWithSPNs', 0),
            delegation_risks=stats.get('UsersWithDelegation', 0) + stats.get('ComputersWithDelegation', 0),
            weak_encryption=len([u for u in self.data.get('Users', [])
                            if any(enc in ['DES', 'RC4'] for enc in u.get('EncryptionTypes', []))
                            or u.get('UseDESKeyOnly', False)]),
            computers_checked=len(self.data.get('ComputerSecurityStatus', [])),
            sections=sections_html,
            recommendations=self.generate_recommendations(),
            graph_data=''  # Graph data is embedded in the graph section HTML
        )


def export_csv(data: Dict[str, Any], output_path: str):
    """Export data to CSV format"""
    import csv
    
    def get_member_of(user: Dict[str, Any]) -> List[str]:
        """Helper function to safely get MemberOf list"""
        member_of = user.get('MemberOf')
        if member_of is None:
            return []
        if isinstance(member_of, list):
            return member_of
        return []
    
    # Export users
    users_file = output_path.replace('.csv', '_users.csv')
    with open(users_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'SamAccountName', 'DisplayName', 'Enabled', 'SPNs', 'PasswordLastSet',
            'DaysSincePasswordChange', 'PasswordNeverExpires', 'EncryptionTypes',
            'TrustedForDelegation', 'MemberOf', 'DaysSinceLastLogon'
        ])
        writer.writeheader()
        for user in data.get('Users', []):
            row = user.copy()
            row['SPNs'] = '; '.join(user.get('SPNs', []))
            row['EncryptionTypes'] = ', '.join(user.get('EncryptionTypes', []))
            row['MemberOf'] = ', '.join(get_member_of(user))
            writer.writerow(row)
    
    # Export computers
    computers_file = output_path.replace('.csv', '_computers.csv')
    with open(computers_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'SamAccountName', 'OperatingSystem', 'Enabled', 'SPNs',
            'TrustedForDelegation', 'ConstrainedDelegation', 'EncryptionTypes'
        ])
        writer.writeheader()
        for computer in data.get('Computers', []):
            row = computer.copy()
            row['SPNs'] = '; '.join(computer.get('SPNs', []))
            row['ConstrainedDelegation'] = '; '.join(computer.get('ConstrainedDelegation', []))
            row['EncryptionTypes'] = ', '.join(computer.get('EncryptionTypes', []))
            writer.writerow(row)
    
    print(f"[+] CSV files exported: {users_file}, {computers_file}")


def main():
    parser = argparse.ArgumentParser(description='Generate AD Security Audit Report')
    parser.add_argument('-i', '--input', default='ad_audit_data.json',
                       help='Input JSON file from PowerShell script')
    parser.add_argument('-o', '--output', default='ad_audit_report.html',
                       help='Output HTML report file')
    parser.add_argument('--csv', action='store_true',
                       help='Also export CSV files')
    parser.add_argument('--json-export', action='store_true',
                       help='Also export processed JSON')
    
    args = parser.parse_args()
    
    # Load JSON data
    try:
        # Use utf-8-sig to handle UTF-8 with or without BOM
        with open(args.input, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[-] Error: Input file '{args.input}' not found.")
        print(f"    Run Get-ADAudit.ps1 first to generate audit data.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[-] Error: Invalid JSON in '{args.input}': {e}")
        sys.exit(1)
    
    # Generate report
    print("[*] Generating HTML report...")
    generator = ADAuditReportGenerator(data)
    html = generator.generate_html()
    
    # Write HTML report
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"[+] HTML report generated: {args.output}")
    
    # Export CSV if requested
    if args.csv:
        export_csv(data, args.output)
    
    # Export JSON if requested
    if args.json_export:
        json_output = args.output.replace('.html', '_processed.json')
        with open(json_output, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[+] Processed JSON exported: {json_output}")


if __name__ == '__main__':
    main()

