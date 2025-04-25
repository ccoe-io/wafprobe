#!/usr/bin/env python3
"""
WAF Testing Report Generator

This module provides enhanced report generation functionality for the WAF testing tool.
"""

import os
import json
import datetime

def escape_html(text):
    """Escape HTML special characters in a string"""
    if not text or not isinstance(text, str):
        return str(text)
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))

def fix_json_structure(data):
    """Fix JSON structure issues with vectors"""
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                data[key] = fix_json_structure(value)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, (dict, list)):
                data[i] = fix_json_structure(item)
    return data

def generate_html_report(results, target_url, output_file):
    """
    Generate an HTML report from test results with improved formatting.
    
    Args:
        results: WAF bypass test results
        target_url: URL that was tested
        output_file: Path to save the HTML report
    """
    # Extract summary data
    summary = results.get("summary", {})
    total_rules = summary.get("total_rules_tested", 0)
    bypasses_found = summary.get("total_bypasses_found", 0)
    rules_with_bypasses = summary.get("rules_with_bypasses", 0)
    rules_with_errors = summary.get("rules_with_errors", 0)
    bypasses_by_component = summary.get("bypasses_by_component", {})
    size_warnings = summary.get("size_warnings", [])
    
    # Get rule results
    rule_results = results.get("results", {})
    
    # Extract hostname for title
    hostname = "unknown"
    try:
        from urllib.parse import urlparse
        hostname = urlparse(target_url).netloc
    except:
        pass
    
    # Start building the HTML report
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Bypass Test Report - {hostname}</title>
    <style>
        :root {{
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --light-color: #f8f9fa;
            --dark-color: #343a40;
        }}
        
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: var(--dark-color);
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        
        header {{
            background-color: var(--primary-color);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        
        h1, h2, h3 {{
            color: var(--primary-color);
            margin-top: 0;
        }}
        
        header h1 {{
            color: white;
            margin-bottom: 10px;
        }}
        
        section {{
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }}
        
        .summary-container {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .summary-box {{
            flex: 1;
            min-width: 150px;
            background-color: var(--light-color);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }}
        
        .summary-box h2 {{
            font-size: 2.5em;
            margin: 0;
        }}
        
        .total-rules h2 {{
            color: var(--secondary-color);
        }}
        
        .rules-bypassed h2 {{
            color: var(--danger-color);
        }}
        
        .bypasses-found h2 {{
            color: var(--danger-color);
        }}
        
        .rules-errors h2 {{
            color: var(--warning-color);
        }}
        
        .chart-row {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
        }}
        
        .chart-box {{
            flex: 1;
            min-width: 300px;
            background-color: var(--light-color);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }}
        
        .chart-container {{
            position: relative;
            height: 300px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        
        th {{
            background-color: var(--light-color);
            font-weight: bold;
        }}
        
        tr:hover {{
            background-color: rgba(0, 0, 0, 0.02);
        }}
        
        .collapsible {{
            background-color: var(--light-color);
            color: var(--primary-color);
            cursor: pointer;
            padding: 18px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 16px;
            font-weight: bold;
            border-radius: 8px;
            margin-bottom: 5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .active, .collapsible:hover {{
            background-color: #e9ecef;
        }}
        
        .content {{
            padding: 0 18px;
            display: none;
            overflow: hidden;
            background-color: white;
            border-radius: 0 0 8px 8px;
            margin-bottom: 20px;
        }}
        
        .status-badge {{
            padding: 5px 10px;
            border-radius: 20px;
            color: white;
            font-size: 14px;
            font-weight: normal;
        }}
        
        .status-passed {{
            background-color: var(--success-color);
        }}
        
        .status-failed {{
            background-color: var(--danger-color);
        }}
        
        .status-error {{
            background-color: var(--warning-color);
        }}
        
        .vector-display {{
            font-family: monospace;
            background-color: #f7f7f7;
            padding: 8px;
            border-radius: 4px;
            overflow-x: auto;
            max-width: 100%;
            word-break: break-all;
        }}
        
        .tab {{
            overflow: hidden;
            border: 1px solid #ccc;
            background-color: #f1f1f1;
            border-radius: 8px 8px 0 0;
        }}
        
        .tab button {{
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 14px 16px;
            transition: 0.3s;
            font-size: 16px;
        }}
        
        .tab button:hover {{
            background-color: #ddd;
        }}
        
        .tab button.active {{
            background-color: var(--primary-color);
            color: white;
        }}
        
        .tabcontent {{
            display: none;
            padding: 20px;
            border: 1px solid #ccc;
            border-top: none;
            border-radius: 0 0 8px 8px;
            animation: fadeEffect 1s;
        }}
        
        @keyframes fadeEffect {{
            from {{opacity: 0;}}
            to {{opacity: 1;}}
        }}
        
        .footer {{
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }}
        
        .warning-box {{
            background-color: #fff3cd;
            color: #856404;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 16px;
        }}
        
        .bypass-details {{
            margin-top: 10px;
            border-left: 3px solid var(--danger-color);
            padding-left: 15px;
        }}
        
        /* New styles for blocked vectors */
        .blocked-vectors {{
            margin-top: 20px;
        }}
        
        .blocked-badge {{
            background-color: var(--success-color);
            padding: 3px 8px;
            border-radius: 4px;
            color: white;
            font-size: 12px;
            margin-left: 6px;
        }}
        
        .bypass-badge {{
            background-color: var(--danger-color);
            padding: 3px 8px;
            border-radius: 4px;
            color: white;
            font-size: 12px;
            margin-left: 6px;
        }}
        
        .vector-section-tabs {{
            overflow: hidden;
            background-color: #f8f9fa;
            border-radius: 4px;
            margin-bottom: 15px;
        }}
        
        .vector-tab-button {{
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 10px 16px;
            transition: 0.3s;
            font-size: 14px;
            border-bottom: 2px solid transparent;
        }}
        
        .vector-tab-button:hover {{
            background-color: #e9ecef;
        }}
        
        .vector-tab-button.active {{
            border-bottom: 2px solid var(--primary-color);
            background-color: #e9ecef;
        }}
        
        .vector-tabcontent {{
            display: none;
            padding: 10px 0;
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <header>
        <h1>WAF Bypass Test Report</h1>
        <p>Target URL: <strong>{target_url}</strong></p>
        <p>Test Date: <strong>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong></p>
    </header>

    <section class="summary">
        <h2>Summary</h2>
        <div class="summary-container">
            <div class="summary-box total-rules">
                <h2>{total_rules}</h2>
                <p>Rules Tested</p>
            </div>
            <div class="summary-box rules-bypassed">
                <h2>{rules_with_bypasses}</h2>
                <p>Rules with Bypasses</p>
            </div>
            <div class="summary-box bypasses-found">
                <h2>{bypasses_found}</h2>
                <p>Total Bypasses Found</p>
            </div>
            <div class="summary-box rules-errors">
                <h2>{rules_with_errors}</h2>
                <p>Rules with Errors</p>
            </div>
        </div>
        
        <div class="chart-row">
            <div class="chart-box">
                <h3>Bypasses by Component</h3>
                <div class="chart-container">
                    <canvas id="componentChart"></canvas>
                </div>
            </div>
            <div class="chart-box">
                <h3>Rules Status Distribution</h3>
                <div class="chart-container">
                    <canvas id="ruleStatusChart"></canvas>
                </div>
            </div>
        </div>
    </section>
    """
    
    # Add size limit warnings section if any
    size_warning_rules = []
    for rule_name, rule_data in rule_results.items():
        if "warnings" in rule_data and rule_data["warnings"]:
            for warning in rule_data["warnings"]:
                if warning.get("type") == "size_limit":
                    size_warning_rules.append((rule_name, warning))
    
    if size_warning_rules:
        html += """
    <section class="size-warnings">
        <h2>Size Limit Warnings</h2>
        <div class="warning-box">
            <p>These warnings indicate that the WAF may not be correctly enforcing size limits. This could potentially allow oversized payloads to bypass protection.</p>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Rule</th>
                    <th>Component</th>
                    <th>Test Size</th>
                    <th>Max Size</th>
                    <th>Status Code</th>
                    <th>Excess</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for rule_name, warning in size_warning_rules:
            component = warning.get("component", "")
            test_size = warning.get("test_size", 0)
            max_size = warning.get("max_size", 0)
            status_code = warning.get("status_code", "")
            excess = test_size - max_size
            excess_percent = (test_size / max_size * 100) if max_size > 0 else 0
            
            html += f"""
                <tr>
                    <td>{rule_name}</td>
                    <td>{component}</td>
                    <td>{test_size} bytes</td>
                    <td>{max_size} bytes</td>
                    <td>{status_code}</td>
                    <td>+{excess} bytes ({excess_percent:.1f}%)</td>
                </tr>
            """
        
        html += """
            </tbody>
        </table>
    </section>
        """
    
    # Create tabs for detailed results
    html += """
    <section>
        <h2>Detailed Results</h2>
        
        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'AllRules')" id="defaultOpen">All Rules</button>
            <button class="tablinks" onclick="openTab(event, 'BypassedRules')">Bypassed Rules</button>
            <button class="tablinks" onclick="openTab(event, 'ErrorRules')">Rules with Errors</button>
        </div>
        
        <div id="AllRules" class="tabcontent" style="display: block;">
    """
    
    # Add all rules to the first tab
    for rule_name, rule_data in rule_results.items():
        bypasses = rule_data.get("bypasses", [])
        errors = rule_data.get("errors", [])
        
        # Extract all test vectors for this rule
        all_vectors = rule_data.get("all_test_results", [])
        
        # Calculate blocked vectors (those in all_vectors but not in bypasses)
        # We need to compare by references or IDs since the objects may not be identical
        bypass_vector_ids = set()
        for bypass in bypasses:
            # Create a unique identifier for each bypass vector
            vector_id = f"{bypass.get('vector', '')}-{bypass.get('component', '')}-{bypass.get('method', '')}"
            bypass_vector_ids.add(vector_id)
        
        blocked_vectors = []
        for vector in all_vectors:
            vector_id = f"{vector.get('vector', '')}-{vector.get('component', '')}-{vector.get('method', '')}"
            if vector_id not in bypass_vector_ids:
                blocked_vectors.append(vector)
        
        status_class = "status-passed"
        status_text = "Passed"
        
        if bypasses:
            status_class = "status-failed"
            status_text = f"Failed ({len(bypasses)} bypasses)"
        elif errors:
            status_class = "status-error"
            status_text = f"Error ({len(errors)} errors)"
        
        rule_description = rule_data.get("description", "No description available")
        
        html += f"""
            <button class="collapsible">
                {rule_name}
                <span class="status-badge {status_class}">{status_text}</span>
            </button>
            <div class="content">
                <p><strong>Description:</strong> {rule_description}</p>
                
                <div class="vector-section-tabs">
                    <button class="vector-tab-button active" onclick="openVectorTab(event, '{rule_name}_bypasses')">Bypasses ({len(bypasses)})</button>
                    <button class="vector-tab-button" onclick="openVectorTab(event, '{rule_name}_blocked')">Blocked Vectors ({len(blocked_vectors)})</button>
                </div>
        """
        
        # Add bypasses section
        html += f"""
                <div id="{rule_name}_bypasses" class="vector-tabcontent" style="display: block;">
        """
        
        # Add bypasses if any
        if bypasses:
            html += """
                <h3>Bypasses</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Vector</th>
                            <th>Component</th>
                            <th>Method</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for bypass in bypasses:
                vector = bypass.get("vector", "")
                component = bypass.get("component", "")
                method = bypass.get("method", "")
                
                # Improve status display
                status_code = bypass.get("status_code", "")
                base_status_code = bypass.get("base_status_code", "")
                
                # Display status codes if available, otherwise fall back to status string
                if status_code:
                    status = f"{status_code}"
                else:
                    status = bypass.get("status", "")
                    
                # Add base status for comparison if available
                status_display = status
                if base_status_code:
                    status_display = f"{status} (Base: {base_status_code})"
                elif bypass.get("base_status", ""):
                    status_display = f"{status} (Base: {bypass.get('base_status', '')})"
                
                # Escape and format the vector for display
                vector_display = escape_html(vector)
                
                html += f"""
                        <tr>
                            <td class="vector-display">{vector_display} <span class="bypass-badge">BYPASS</span></td>
                            <td>{component}</td>
                            <td>{method}</td>
                            <td>{status_display}</td>
                        </tr>
                """
            
            html += """
                    </tbody>
                </table>
            """
        else:
            html += """
                <p>No bypasses found for this rule.</p>
            """
        
        html += """
                </div>
        """
        
        # Add blocked vectors section
        html += f"""
                <div id="{rule_name}_blocked" class="vector-tabcontent">
                <h3>Blocked Vectors</h3>
        """
        
        # Check if we have structured blocked vector data
        if blocked_vectors:
            html += """
                <table>
                    <thead>
                        <tr>
                            <th>Vector</th>
                            <th>Component</th>
                            <th>Method</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for vector in blocked_vectors:
                vector_text = vector.get("vector", "")
                component = vector.get("component", "")
                method = vector.get("method", "")
                
                # Improve status display
                status_code = vector.get("status_code", "")
                base_status_code = vector.get("base_status_code", "")
                
                # Display status codes if available
                status = f"{status_code}" if status_code else vector.get("status", "Unknown")
                
                # Add base status for comparison if available
                status_display = status
                if base_status_code:
                    status_display = f"{status} (Base: {base_status_code})"
                elif vector.get("base_status", ""):
                    status_display = f"{status} (Base: {vector.get('base_status', '')})"
                
                # Escape and format the vector for display
                vector_display = escape_html(vector_text)
                
                html += f"""
                        <tr>
                            <td class="vector-display">{vector_display} <span class="blocked-badge">BLOCKED</span></td>
                            <td>{component}</td>
                            <td>{method}</td>
                            <td>{status_display}</td>
                        </tr>
                """
            
            html += """
                    </tbody>
                </table>
            """
        else:
            # If we don't have structured data, provide a message
            html += """
                <p>Blocked vector details are not available in this report.</p>
                <p>To see detailed blocked vector information, please update the test configuration to record all test results.</p>
            """
        
        html += """
                </div>
        """
        
        # Add errors if any
        if errors:
            html += """
                <h3>Errors</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Component</th>
                            <th>Error</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for error in errors:
                html += f"""
                        <tr>
                            <td>{error.get("component", "")}</td>
                            <td>{escape_html(error.get("message", ""))}</td>
                        </tr>
                """
            
            html += """
                    </tbody>
                </table>
            """
        
        html += """
            </div>
        """
    
    html += """
        </div>
        
        <div id="BypassedRules" class="tabcontent">
    """
    
    # Add bypassed rules to the second tab
    bypassed_rules_count = 0
    for rule_name, rule_data in rule_results.items():
        bypasses = rule_data.get("bypasses", [])
        if not bypasses:
            continue
        
        bypassed_rules_count += 1
        rule_description = rule_data.get("description", "No description available")
        
        html += f"""
            <button class="collapsible">
                {rule_name}
                <span class="status-badge status-failed">Failed ({len(bypasses)} bypasses)</span>
            </button>
            <div class="content">
                <p><strong>Description:</strong> {rule_description}</p>
                
                <h3>Bypasses</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Vector</th>
                            <th>Component</th>
                            <th>Method</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for bypass in bypasses:
            vector = bypass.get("vector", "")
            component = bypass.get("component", "")
            method = bypass.get("method", "")
            
            # Improve status display
            status_code = bypass.get("status_code", "")
            base_status_code = bypass.get("base_status_code", "")
            
            # Display status codes if available
            status = f"{status_code}" if status_code else bypass.get("status", "Unknown")
            
            # Add base status for comparison if available
            status_display = status
            if base_status_code:
                status_display = f"{status} (Base: {base_status_code})"
            elif bypass.get("base_status", ""):
                status_display = f"{status} (Base: {bypass.get('base_status', '')})"
            
            # Escape and format the vector for display
            vector_display = escape_html(vector)
            
            html += f"""
                        <tr>
                            <td class="vector-display">{vector_display}</td>
                            <td>{component}</td>
                            <td>{method}</td>
                            <td>{status_display}</td>
                        </tr>
            """
        
        html += """
                    </tbody>
                </table>
            </div>
        """
    
    if bypassed_rules_count == 0:
        html += """
            <p>No rules were bypassed. Great job!</p>
        """
    
    html += """
        </div>
        
        <div id="ErrorRules" class="tabcontent">
    """
    
    # Add rules with errors to the third tab
    error_rules_count = 0
    for rule_name, rule_data in rule_results.items():
        errors = rule_data.get("errors", [])
        if not errors:
            continue
        
        error_rules_count += 1
        rule_description = rule_data.get("description", "No description available")
        
        html += f"""
            <button class="collapsible">
                {rule_name}
                <span class="status-badge status-error">Error ({len(errors)} errors)</span>
            </button>
            <div class="content">
                <p><strong>Description:</strong> {rule_description}</p>
                
                <h3>Errors</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Component</th>
                            <th>Error</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for error in errors:
            html += f"""
                        <tr>
                            <td>{error.get("component", "")}</td>
                            <td>{escape_html(error.get("message", ""))}</td>
                        </tr>
            """
        
        html += """
                    </tbody>
                </table>
            </div>
        """
    
    if error_rules_count == 0:
        html += """
            <p>No rules had errors. Great job!</p>
        """
    
    html += """
        </div>
    </section>
    """
    
    # Close the HTML document with footer and JavaScript for functionality
    html += f"""
    <div class="footer">
        <p>Report generated by the WAF Testing Tool | Target: {hostname} | Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <script>
        // Collapsible sections
        var coll = document.getElementsByClassName("collapsible");
        for (var i = 0; i < coll.length; i++) {{
            coll[i].addEventListener("click", function() {{
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.display === "block") {{
                    content.style.display = "none";
                }} else {{
                    content.style.display = "block";
                }}
            }});
        }}
        
        // Auto-expand sections with bypasses in the bypassed tab
        function autoExpandBypasses() {{
            if (document.getElementById('BypassedRules').style.display === 'block') {{
                var bypassedSections = document.getElementById('BypassedRules').getElementsByClassName("collapsible");
                for (var i = 0; i < bypassedSections.length; i++) {{
                    if (!bypassedSections[i].classList.contains('active')) {{
                        bypassedSections[i].click();
                    }}
                }}
            }}
        }}
        
        // Tab functionality
        function openTab(evt, tabName) {{
            var i, tabcontent, tablinks;
            
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {{
                tabcontent[i].style.display = "none";
            }}
            
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {{
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }}
            
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
            
            if (tabName === 'BypassedRules') {{
                setTimeout(autoExpandBypasses, 100);
            }}
        }}
        
        // Vector tabs functionality (for bypass/blocked sections)
        function openVectorTab(evt, tabName) {{
            var i, tabcontent, tablinks;
            
            // Get the parent element (content div)
            var parent = evt.currentTarget.parentElement.parentElement;
            
            // Find all vector tab content within this parent
            tabcontent = parent.getElementsByClassName("vector-tabcontent");
            for (i = 0; i < tabcontent.length; i++) {{
                tabcontent[i].style.display = "none";
            }}
            
            // Find all vector tab buttons within this parent
            tablinks = parent.getElementsByClassName("vector-tab-button");
            for (i = 0; i < tablinks.length; i++) {{
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }}
            
            // Show the current tab
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }}
        
        // Chart for bypasses by component
        var componentData = {json.dumps(bypasses_by_component)};
        var components = Object.keys(componentData);
        var bypassValues = components.map(function(key) {{ return componentData[key]; }});
        
        var ctx1 = document.getElementById('componentChart').getContext('2d');
        new Chart(ctx1, {{
            type: 'bar',
            data: {{
                labels: components,
                datasets: [{{
                    label: 'Number of Bypasses',
                    data: bypassValues,
                    backgroundColor: 'rgba(231, 76, 60, 0.5)',
                    borderColor: 'rgba(231, 76, 60, 1)',
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        title: {{
                            display: true,
                            text: 'Number of Bypasses'
                        }}
                    }},
                    x: {{
                        title: {{
                            display: true,
                            text: 'Component'
                        }}
                    }}
                }},
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }}
            }}
        }});
        
        // Chart for rule status distribution
        var ruleStatusData = [
            {rules_with_bypasses},
            {total_rules - rules_with_bypasses - rules_with_errors},
            {rules_with_errors}
        ];
        
        var ctx2 = document.getElementById('ruleStatusChart').getContext('2d');
        new Chart(ctx2, {{
            type: 'pie',
            data: {{
                labels: [
                    'Rules with Bypasses',
                    'Rules Passed',
                    'Rules with Errors'
                ],
                datasets: [{{
                    data: ruleStatusData,
                    backgroundColor: [
                        'rgba(231, 76, 60, 0.7)',
                        'rgba(46, 204, 113, 0.7)',
                        'rgba(155, 89, 182, 0.7)'
                    ],
                    borderColor: [
                        'rgba(231, 76, 60, 1)',
                        'rgba(46, 204, 113, 1)',
                        'rgba(155, 89, 182, 1)'
                    ],
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'right'
                    }},
                    title: {{
                        display: true,
                        text: 'Rule Test Results'
                    }}
                }}
            }}
        }});
        
        // Open the default tab on load
        document.getElementById("defaultOpen").click();
    </script>
</body>
</html>
    """
    
    # Save the HTML report
    try:
        # Create directory if it doesn't exist
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        with open(output_file, 'w') as f:
            f.write(html)
        return output_file
    except Exception as e:
        raise Exception(f"Error writing HTML report to {output_file}: {e}") 