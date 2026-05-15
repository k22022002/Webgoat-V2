/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hsqldb.jdbc.JDBCResultSet.CONCUR_UPDATABLE;
import static org.hsqldb.jdbc.JDBCResultSet.TYPE_SCROLL_SENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint.9.1",
      "SqlStringInjectionHint.9.2",
      "SqlStringInjectionHint.9.3",
      "SqlStringInjectionHint.9.4",
      "SqlStringInjectionHint.9.5"
    })
public class SqlInjectionLesson9 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson9(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack9")
  @ResponseBody
  public AttackResult completed(@RequestParam String name, @RequestParam String auth_tan) {
    return injectableQueryIntegrity(name, auth_tan);
  }

  protected AttackResult injectableQueryIntegrity(String name, String auth_tan) {
    StringBuilder output = new StringBuilder();
    String queryInjection =
        "SELECT * FROM employees WHERE last_name = '"
            + name
            + "' AND auth_tan = '"
            + auth_tan
            + "'";
            
    // Connection đã được quản lý tốt bằng try-with-resources
    try (Connection connection = dataSource.getConnection()) {
      int oldMaxSalary = this.getMaxSalary(connection);
      int oldSumSalariesOfOtherEmployees = this.getSumSalariesOfOtherEmployees(connection);
      
      // begin transaction
      connection.setAutoCommit(false);
      
      // [VÁ LỖI] Quản lý an toàn Statement thực thi query bằng try-with-resources
      try (Statement statement = connection.createStatement(TYPE_SCROLL_SENSITIVE, CONCUR_UPDATABLE)) {
          SqlInjectionLesson8.log(connection, queryInjection);
          statement.execute(queryInjection);
      } // <--- Statement tự động đóng sau khi block này kết thúc

      // check new sum of salaries other employees and new salaries of John
      int newJohnSalary = this.getJohnSalary(connection);
      int newSumSalariesOfOtherEmployees = this.getSumSalariesOfOtherEmployees(connection);
      
      if (newJohnSalary > oldMaxSalary
          && newSumSalariesOfOtherEmployees == oldSumSalariesOfOtherEmployees) {
        // success commit
        connection.commit(); 
        connection.setAutoCommit(true);
        // [VÁ LỖI] Gọi hàm lấy dữ liệu bảng HTML đã được refactor an toàn
        output.append(this.getEmployeesTable(connection));
        return success(this).feedback("sql-injection.9.success").output(output.toString()).build();
      }
      
      // failed rollback
      connection.rollback();
      // [VÁ LỖI] Gọi hàm lấy dữ liệu bảng HTML đã được refactor an toàn
      return failed(this)
          .feedback("sql-injection.9.one")
          .output(this.getEmployeesTable(connection))
          .build();
          
    } catch (SQLException e) {
      return failed(this)
          .output("<br><span class='feedback-negative'>" + e.getMessage() + "</span>")
          .build();
    }
  }

  private int getSqlInt(Connection connection, String query) throws SQLException {
    // [VÁ LỖI] Đảm bảo cả Statement và ResultSet đều tự động đóng khi return giá trị
    try (Statement statement = connection.createStatement(TYPE_SCROLL_SENSITIVE, CONCUR_UPDATABLE);
         ResultSet results = statement.executeQuery(query)) {
        results.first();
        return results.getInt(1);
    } // <--- Cả ResultSet và Statement được dọn dẹp sạch sẽ
  }

  private int getMaxSalary(Connection connection) throws SQLException {
    String query = "SELECT max(salary) FROM employees";
    return this.getSqlInt(connection, query);
  }

  private int getSumSalariesOfOtherEmployees(Connection connection) throws SQLException {
    String query = "SELECT sum(salary) FROM employees WHERE auth_tan != '3SL99A'";
    return this.getSqlInt(connection, query);
  }

  private int getJohnSalary(Connection connection) throws SQLException {
    String query = "SELECT salary FROM employees WHERE auth_tan = '3SL99A'";
    return this.getSqlInt(connection, query);
  }

  // [VÁ LỖI] Refactor thiết kế: Chuyển thẳng ResultSet sang String (HTML) để không bị rò rỉ bộ nhớ ra ngoài
  private String getEmployeesTable(Connection connection) throws SQLException {
    String query = "SELECT * FROM employees ORDER BY salary DESC";
    try (Statement statement = connection.createStatement(TYPE_SCROLL_SENSITIVE, CONCUR_UPDATABLE);
         ResultSet rs = statement.executeQuery(query)) {
        return SqlInjectionLesson8.generateTable(rs);
    } // <--- ResultSet được dùng xong và tự động đóng ngay lập tức
  }
}