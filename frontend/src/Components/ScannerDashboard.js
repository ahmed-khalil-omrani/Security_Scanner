import React, { useState } from "react";
import axios from "axios";
import "./ScannerDashboard.css";

const ScannerDashboard = () => {
  const [url, setUrl] = useState("");
  const [maxPages, setMaxPages] = useState(30);
  const [scanTypes, setScanTypes] = useState({
    sql_injection: true,
    xss: true,
    csrf: true,
    ssl: true,
    headers: true,
  });
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  const handleScanTypeChange = (type) => {
    setScanTypes({
      ...scanTypes,
      [type]: !scanTypes[type],
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setResults(null);

    const selectedTypes = Object.keys(scanTypes).filter(
      (key) => scanTypes[key]
    );

    try {
      const response = await axios.post("http://localhost:8000/api/scan", {
        url: url,
        max_pages: parseInt(maxPages),
        scan_types: selectedTypes,
      });

      setResults(response.data.result);
    } catch (err) {
      setError(
        err.response?.data?.detail || "An error occurred during scanning"
      );
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: "#dc3545",
      HIGH: "#fd7e14",
      MEDIUM: "#ffc107",
      LOW: "#17a2b8",
    };
    return colors[severity] || "#6c757d";
  };

  const calculatePercentage = (count, total) => {
    if (total === 0) return 0;
    return ((count / total) * 100).toFixed(1);
  };

  const getVulnerabilityTypeStats = (vulnerabilities) => {
    const typeCount = {};

    vulnerabilities.forEach((vuln) => {
      if (typeCount[vuln.type]) {
        typeCount[vuln.type]++;
      } else {
        typeCount[vuln.type] = 1;
      }
    });

    return Object.entries(typeCount)
      .map(([type, count]) => ({
        type,
        count,
        percentage: calculatePercentage(count, vulnerabilities.length),
      }))
      .sort((a, b) => b.count - a.count);
  };

  const getVulnerabilityTypeBySeverity = (vulnerabilities) => {
    const stats = {};

    vulnerabilities.forEach((vuln) => {
      const key = `${vuln.type}|${vuln.severity}`;
      if (stats[key]) {
        stats[key].count++;
      } else {
        stats[key] = {
          type: vuln.type,
          severity: vuln.severity,
          count: 1,
        };
      }
    });

    return Object.values(stats).sort((a, b) => {
      const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      return (
        severityOrder[a.severity] - severityOrder[b.severity] ||
        b.count - a.count
      );
    });
  };

  const generateHTMLReport = (scanResults) => {
    const typeStats = getVulnerabilityTypeStats(scanResults.vulnerabilities);
    const typeSeverityStats = getVulnerabilityTypeBySeverity(
      scanResults.vulnerabilities
    );

    const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - ${scanResults.scan_id}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }

        .report-container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 10px;
        }

        .report-header {
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 3px solid #667eea;
            padding-bottom: 20px;
        }

        .report-header h1 {
            color: #2c3e50;
            font-size: 2.5rem;
            margin-bottom: 10px;
        }

        .report-header .scan-id {
            color: #6c757d;
            font-size: 0.9rem;
        }

        .report-header .scan-date {
            color: #495057;
            font-size: 1rem;
            margin-top: 10px;
        }

        .summary-section {
            margin-bottom: 40px;
        }

        .summary-section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8rem;
            border-left: 4px solid #667eea;
            padding-left: 15px;
        }

        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
        }

        .summary-card h3 {
            font-size: 3rem;
            margin-bottom: 10px;
        }

        .summary-card p {
            font-size: 1.1rem;
            opacity: 0.9;
        }

        .severity-breakdown {
            margin-bottom: 30px;
        }

        .severity-row {
            display: grid;
            grid-template-columns: 100px 1fr 80px 80px;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
        }

        .severity-label {
            font-weight: 600;
            text-transform: uppercase;
        }

        .severity-bar-container {
            background: #e9ecef;
            height: 30px;
            border-radius: 5px;
            overflow: hidden;
            position: relative;
        }

        .severity-bar-fill {
            height: 100%;
            border-radius: 5px;
            transition: width 0.5s ease;
        }

        .severity-bar-fill.critical { background-color: #dc3545; }
        .severity-bar-fill.high { background-color: #fd7e14; }
        .severity-bar-fill.medium { background-color: #ffc107; }
        .severity-bar-fill.low { background-color: #17a2b8; }

        .count, .percentage {
            font-weight: 600;
            text-align: center;
        }

        .type-distribution {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .type-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }

        .type-card h4 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.1rem;
        }

        .type-percentage {
            font-size: 2rem;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 10px;
        }

        .type-bar {
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 10px;
        }

        .type-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        }

        .type-count {
            color: #6c757d;
            font-size: 0.9rem;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }

        thead {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        th, td {
            padding: 15px;
            text-align: left;
        }

        tbody tr:nth-child(even) {
            background: #f8f9fa;
        }

        tbody tr:hover {
            background: #e9ecef;
        }

        .severity-badge {
            padding: 5px 12px;
            border-radius: 20px;
            color: white;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            display: inline-block;
        }

        .severity-badge.critical { background-color: #dc3545; }
        .severity-badge.high { background-color: #fd7e14; }
        .severity-badge.medium { background-color: #ffc107; color: #333; }
        .severity-badge.low { background-color: #17a2b8; }

        .vulnerability-card {
            background: #f8f9fa;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            border-left: 4px solid #dee2e6;
            page-break-inside: avoid;
        }

        .vuln-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
        }

        .vuln-title {
            font-size: 1.3rem;
            color: #2c3e50;
            flex-grow: 1;
        }

        .vuln-number {
            color: #6c757d;
            font-weight: 600;
        }

        .vuln-details {
            margin-top: 15px;
        }

        .vuln-details p {
            margin-bottom: 10px;
        }

        .vuln-details strong {
            color: #495057;
        }

        code {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #e83e8c;
            word-break: break-all;
        }

        .recommendation {
            margin-top: 15px;
            padding: 15px;
            background: #e7f3ff;
            border-left: 3px solid #0066cc;
            border-radius: 5px;
        }

        .recommendation strong {
            color: #0066cc;
            display: block;
            margin-bottom: 8px;
        }

        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #e9ecef;
            text-align: center;
            color: #6c757d;
            font-size: 0.9rem;
        }

        @media print {
            body {
                background: white;
                padding: 0;
            }
            .report-container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="report-container">
        <div class="report-header">
            <h1>🔒 Security Scan Report</h1>
            <p class="scan-id">Scan ID: ${scanResults.scan_id}</p>
            <p class="scan-date">Generated: ${new Date(
              scanResults.end_time
            ).toLocaleString()}</p>
            <p><strong>Target:</strong> ${scanResults.target}</p>
        </div>

        <div class="summary-section">
            <h2>Executive Summary</h2>
            <div class="summary-cards">
                <div class="summary-card">
                    <h3>${scanResults.urls_found}</h3>
                    <p>URLs Crawled</p>
                </div>
                <div class="summary-card">
                    <h3>${scanResults.forms_found}</h3>
                    <p>Forms Found</p>
                </div>
                <div class="summary-card">
                    <h3>${scanResults.total_vulnerabilities}</h3>
                    <p>Total Issues</p>
                </div>
            </div>

            <h3>Severity Breakdown</h3>
            <div class="severity-breakdown">
                <div class="severity-row">
                    <span class="severity-label">CRITICAL</span>
                    <div class="severity-bar-container">
                        <div class="severity-bar-fill critical" style="width: ${calculatePercentage(
                          scanResults.critical,
                          scanResults.total_vulnerabilities
                        )}%"></div>
                    </div>
                    <span class="count">${scanResults.critical}</span>
                    <span class="percentage">${calculatePercentage(
                      scanResults.critical,
                      scanResults.total_vulnerabilities
                    )}%</span>
                </div>
                <div class="severity-row">
                    <span class="severity-label">HIGH</span>
                    <div class="severity-bar-container">
                        <div class="severity-bar-fill high" style="width: ${calculatePercentage(
                          scanResults.high,
                          scanResults.total_vulnerabilities
                        )}%"></div>
                    </div>
                    <span class="count">${scanResults.high}</span>
                    <span class="percentage">${calculatePercentage(
                      scanResults.high,
                      scanResults.total_vulnerabilities
                    )}%</span>
                </div>
                <div class="severity-row">
                    <span class="severity-label">MEDIUM</span>
                    <div class="severity-bar-container">
                        <div class="severity-bar-fill medium" style="width: ${calculatePercentage(
                          scanResults.medium,
                          scanResults.total_vulnerabilities
                        )}%"></div>
                    </div>
                    <span class="count">${scanResults.medium}</span>
                    <span class="percentage">${calculatePercentage(
                      scanResults.medium,
                      scanResults.total_vulnerabilities
                    )}%</span>
                </div>
                <div class="severity-row">
                    <span class="severity-label">LOW</span>
                    <div class="severity-bar-container">
                        <div class="severity-bar-fill low" style="width: ${calculatePercentage(
                          scanResults.low,
                          scanResults.total_vulnerabilities
                        )}%"></div>
                    </div>
                    <span class="count">${scanResults.low}</span>
                    <span class="percentage">${calculatePercentage(
                      scanResults.low,
                      scanResults.total_vulnerabilities
                    )}%</span>
                </div>
            </div>
        </div>

        ${
          typeStats.length > 0
            ? `
        <div class="summary-section">
            <h2>Vulnerability Type Distribution</h2>
            <div class="type-distribution">
                ${typeStats
                  .map(
                    (stat) => `
                <div class="type-card">
                    <h4>${stat.type}</h4>
                    <div class="type-percentage">${stat.percentage}%</div>
                    <div class="type-bar">
                        <div class="type-bar-fill" style="width: ${
                          stat.percentage
                        }%"></div>
                    </div>
                    <div class="type-count">${stat.count} issue${
                      stat.count !== 1 ? "s" : ""
                    }</div>
                </div>
                `
                  )
                  .join("")}
            </div>
        </div>
        `
            : ""
        }

        ${
          typeSeverityStats.length > 0
            ? `
        <div class="summary-section">
            <h2>Vulnerabilities by Type & Severity</h2>
            <table>
                <thead>
                    <tr>
                        <th>Vulnerability Type</th>
                        <th>Severity</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
                    ${typeSeverityStats
                      .map(
                        (stat) => `
                    <tr>
                        <td>${stat.type}</td>
                        <td><span class="severity-badge ${stat.severity.toLowerCase()}">${
                          stat.severity
                        }</span></td>
                        <td>${stat.count}</td>
                        <td>${calculatePercentage(
                          stat.count,
                          scanResults.total_vulnerabilities
                        )}%</td>
                    </tr>
                    `
                      )
                      .join("")}
                </tbody>
            </table>
        </div>
        `
            : ""
        }

        <div class="summary-section">
            <h2>Detailed Vulnerability Report</h2>
            ${
              scanResults.vulnerabilities.length === 0
                ? `
            <div style="text-align: center; padding: 40px; background: #d4edda; color: #155724; border-radius: 8px;">
                ✅ No vulnerabilities found! Your application appears secure.
            </div>
            `
                : scanResults.vulnerabilities
                    .map(
                      (vuln, index) => `
            <div class="vulnerability-card">
                <div class="vuln-header">
                    <span class="severity-badge ${vuln.severity.toLowerCase()}">${
                        vuln.severity
                      }</span>
                    <h3 class="vuln-title">${vuln.type}</h3>
                    <span class="vuln-number">#${index + 1}</span>
                </div>
                <div class="vuln-details">
                    <p><strong>URL:</strong> <code>${vuln.url}</code></p>
                    <p><strong>Description:</strong> ${vuln.description}</p>
                    ${
                      vuln.payload
                        ? `<p><strong>Payload:</strong> <code>${vuln.payload}</code></p>`
                        : ""
                    }
                    ${
                      vuln.evidence
                        ? `<p><strong>Evidence:</strong> ${vuln.evidence}</p>`
                        : ""
                    }
                    <div class="recommendation">
                        <strong>💡 Recommendation:</strong>
                        <p>${vuln.recommendation}</p>
                    </div>
                </div>
            </div>
            `
                    )
                    .join("")
            }
        </div>

        <div class="footer">
            <p><strong>OWASP Security Scanner</strong></p>
            <p>Report generated on ${new Date().toLocaleString()}</p>
            <p style="margin-top: 10px; color: #dc3545;">⚠️ This report is confidential. Only scan websites you own or have permission to test.</p>
        </div>
    </div>
</body>
</html>
    `;

    // Create blob and download
    const blob = new Blob([htmlContent], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `security_scan_report_${scanResults.scan_id}.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="scanner-dashboard">
      <header className="dashboard-header">
        <h1>🔒 OWASP Security Scanner</h1>
        <p className="warning">
          ⚠️ Only scan websites you own or have permission to test
        </p>
      </header>

      <div className="scan-form-container">
        <form onSubmit={handleSubmit} className="scan-form">
          <div className="form-group">
            <label htmlFor="url">Target URL:</label>
            <input
              type="url"
              id="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="maxPages">Max Pages to Crawl:</label>
            <input
              type="number"
              id="maxPages"
              value={maxPages}
              onChange={(e) => setMaxPages(e.target.value)}
              min="1"
              max="100"
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label>Scan Types:</label>
            <div className="checkbox-group">
              {Object.keys(scanTypes).map((type) => (
                <label key={type} className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={scanTypes[type]}
                    onChange={() => handleScanTypeChange(type)}
                    disabled={loading}
                  />
                  <span>{type.replace("_", " ").toUpperCase()}</span>
                </label>
              ))}
            </div>
          </div>

          <button type="submit" className="scan-button" disabled={loading}>
            {loading ? "🔄 Scanning..." : "🚀 Start Scan"}
          </button>
        </form>
      </div>

      {error && (
        <div className="error-message">
          <strong>Error:</strong> {error}
        </div>
      )}

      {loading && (
        <div className="loading-container">
          <div className="spinner"></div>
          <p>Scanning in progress... This may take a few minutes.</p>
        </div>
      )}

      {results && !loading && (
        <div className="results-container">
          <h2>Scan Results</h2>

          <div className="summary-cards">
            <div className="summary-card">
              <h3>{results.urls_found}</h3>
              <p>URLs Crawled</p>
            </div>
            <div className="summary-card">
              <h3>{results.forms_found}</h3>
              <p>Forms Found</p>
            </div>
            <div className="summary-card">
              <h3>{results.total_vulnerabilities}</h3>
              <p>Total Issues</p>
            </div>
          </div>

          {/* Severity Breakdown with Percentages */}
          <div className="severity-breakdown">
            <h3>Severity Breakdown</h3>
            <div className="severity-bars">
              <div className="severity-bar">
                <span className="severity-label">CRITICAL</span>
                <div className="bar-container">
                  <div
                    className="bar critical"
                    style={{
                      width:
                        results.total_vulnerabilities > 0
                          ? `${
                              (results.critical /
                                results.total_vulnerabilities) *
                              100
                            }%`
                          : "0%",
                    }}
                  ></div>
                  <span className="count">{results.critical}</span>
                  <span className="percentage">
                    (
                    {calculatePercentage(
                      results.critical,
                      results.total_vulnerabilities
                    )}
                    %)
                  </span>
                </div>
              </div>
              <div className="severity-bar">
                <span className="severity-label">HIGH</span>
                <div className="bar-container">
                  <div
                    className="bar high"
                    style={{
                      width:
                        results.total_vulnerabilities > 0
                          ? `${
                              (results.high / results.total_vulnerabilities) *
                              100
                            }%`
                          : "0%",
                    }}
                  ></div>
                  <span className="count">{results.high}</span>
                  <span className="percentage">
                    (
                    {calculatePercentage(
                      results.high,
                      results.total_vulnerabilities
                    )}
                    %)
                  </span>
                </div>
              </div>
              <div className="severity-bar">
                <span className="severity-label">MEDIUM</span>
                <div className="bar-container">
                  <div
                    className="bar medium"
                    style={{
                      width:
                        results.total_vulnerabilities > 0
                          ? `${
                              (results.medium / results.total_vulnerabilities) *
                              100
                            }%`
                          : "0%",
                    }}
                  ></div>
                  <span className="count">{results.medium}</span>
                  <span className="percentage">
                    (
                    {calculatePercentage(
                      results.medium,
                      results.total_vulnerabilities
                    )}
                    %)
                  </span>
                </div>
              </div>
              <div className="severity-bar">
                <span className="severity-label">LOW</span>
                <div className="bar-container">
                  <div
                    className="bar low"
                    style={{
                      width:
                        results.total_vulnerabilities > 0
                          ? `${
                              (results.low / results.total_vulnerabilities) *
                              100
                            }%`
                          : "0%",
                    }}
                  ></div>
                  <span className="count">{results.low}</span>
                  <span className="percentage">
                    (
                    {calculatePercentage(
                      results.low,
                      results.total_vulnerabilities
                    )}
                    %)
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Vulnerability Type Distribution */}
          {results.vulnerabilities.length > 0 && (
            <div className="vulnerability-type-distribution">
              <h3>Vulnerability Type Distribution</h3>
              <div className="type-stats-grid">
                {getVulnerabilityTypeStats(results.vulnerabilities).map(
                  (stat, index) => (
                    <div key={index} className="type-stat-card">
                      <div className="type-stat-header">
                        <h4>{stat.type}</h4>
                        <span className="type-percentage">
                          {stat.percentage}%
                        </span>
                      </div>
                      <div className="type-stat-bar">
                        <div
                          className="type-bar-fill"
                          style={{ width: `${stat.percentage}%` }}
                        ></div>
                      </div>
                      <div className="type-stat-count">
                        {stat.count} issue{stat.count !== 1 ? "s" : ""}
                      </div>
                    </div>
                  )
                )}
              </div>
            </div>
          )}

          {/* Vulnerability Details by Type and Severity */}
          {results.vulnerabilities.length > 0 && (
            <div className="vulnerability-type-severity">
              <h3>Vulnerabilities by Type & Severity</h3>
              <div className="type-severity-table">
                <table>
                  <thead>
                    <tr>
                      <th>Vulnerability Type</th>
                      <th>Severity</th>
                      <th>Count</th>
                      <th>Percentage</th>
                    </tr>
                  </thead>
                  <tbody>
                    {getVulnerabilityTypeBySeverity(
                      results.vulnerabilities
                    ).map((stat, index) => (
                      <tr key={index}>
                        <td>{stat.type}</td>
                        <td>
                          <span
                            className="severity-badge-small"
                            style={{
                              backgroundColor: getSeverityColor(stat.severity),
                            }}
                          >
                            {stat.severity}
                          </span>
                        </td>
                        <td>{stat.count}</td>
                        <td>
                          <div className="inline-bar-container">
                            <div
                              className="inline-bar"
                              style={{
                                width: `${calculatePercentage(
                                  stat.count,
                                  results.total_vulnerabilities
                                )}%`,
                                backgroundColor: getSeverityColor(
                                  stat.severity
                                ),
                              }}
                            ></div>
                            <span className="inline-percentage">
                              {calculatePercentage(
                                stat.count,
                                results.total_vulnerabilities
                              )}
                              %
                            </span>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Detailed Vulnerabilities List */}
          <div className="vulnerabilities-list">
            <h3>Detailed Vulnerability Report</h3>
            {results.vulnerabilities.length === 0 ? (
              <div className="no-vulns">
                ✅ No vulnerabilities found! Your application appears secure.
              </div>
            ) : (
              results.vulnerabilities.map((vuln, index) => (
                <div key={index} className="vulnerability-card">
                  <div className="vuln-header">
                    <span
                      className="severity-badge"
                      style={{
                        backgroundColor: getSeverityColor(vuln.severity),
                      }}
                    >
                      {vuln.severity}
                    </span>
                    <h4>{vuln.type}</h4>
                    <span className="vuln-number">#{index + 1}</span>
                  </div>
                  <div className="vuln-body">
                    <p>
                      <strong>URL:</strong> <code>{vuln.url}</code>
                    </p>
                    <p>
                      <strong>Description:</strong> {vuln.description}
                    </p>
                    {vuln.payload && (
                      <p>
                        <strong>Payload:</strong> <code>{vuln.payload}</code>
                      </p>
                    )}
                    {vuln.evidence && (
                      <p>
                        <strong>Evidence:</strong> {vuln.evidence}
                      </p>
                    )}
                    <div className="recommendation">
                      <strong>💡 Recommendation:</strong>
                      <p>{vuln.recommendation}</p>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Summary Statistics */}
          {results.vulnerabilities.length > 0 && (
            <div className="summary-statistics">
              <h3>Summary Statistics</h3>
              <div className="stats-grid">
                <div className="stat-item">
                  <span className="stat-label">Most Common Vulnerability:</span>
                  <span className="stat-value">
                    {getVulnerabilityTypeStats(results.vulnerabilities)[0].type}
                    <small>
                      {" "}
                      (
                      {
                        getVulnerabilityTypeStats(results.vulnerabilities)[0]
                          .count
                      }{" "}
                      occurrences)
                    </small>
                  </span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">Critical + High Issues:</span>
                  <span className="stat-value">
                    {results.critical + results.high}
                    <small>
                      {" "}
                      (
                      {calculatePercentage(
                        results.critical + results.high,
                        results.total_vulnerabilities
                      )}
                      %)
                    </small>
                  </span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">Scan Completion Time:</span>
                  <span className="stat-value">
                    {new Date(results.end_time).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>
          )}

          <div className="actions">
            <button
              className="download-button"
              onClick={() => {
                const dataStr = JSON.stringify(results, null, 2);
                const dataUri =
                  "data:application/json;charset=utf-8," +
                  encodeURIComponent(dataStr);
                const exportFileDefaultName = `scan_report_${results.scan_id}.json`;
                const linkElement = document.createElement("a");
                linkElement.setAttribute("href", dataUri);
                linkElement.setAttribute("download", exportFileDefaultName);
                linkElement.click();
              }}
            >
              📥 Download JSON
            </button>
            <button
              className="download-html-button"
              onClick={() => generateHTMLReport(results)}
            >
              📄 Download HTML Report
            </button>
            <button className="print-button" onClick={() => window.print()}>
              🖨️ Print Report
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScannerDashboard;
