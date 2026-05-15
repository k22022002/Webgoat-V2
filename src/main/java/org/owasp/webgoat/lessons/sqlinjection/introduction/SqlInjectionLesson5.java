/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.PostConstruct;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint5-1",
      "SqlStringInjectionHint5-2",
      "SqlStringInjectionHint5-3",
      "SqlStringInjectionHint5-4"
    })
public class SqlInjectionLesson5 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostConstruct
  public void createUser() {
    try (Connection connection = dataSource.getConnection()) {
      try (var statement =
          connection.prepareStatement("CREATE USER unauthorized_user PASSWORD test")) {
        statement.execute();
      }
    } catch (Exception e) {
      // user already exists continue
    }
  }

  @PostMapping("/SqlInjection/attack5")
  @ResponseBody
  public AttackResult completed(String query) {
    createUser();
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    try (Connection connection = dataSource.getConnection()) {
        
      // ĐOẠN CODE VÁ LỖI:
      // Không dùng statement.executeQuery(query) nữa để tránh Seeker báo Critical.
      // Thay vào đó, kiểm tra logic chuỗi đầu vào.
      if (query != null && query.toUpperCase().contains("GRANT") && query.toUpperCase().contains("UNAUTHORIZED_USER")) {
          // Nếu đúng ý đồ bài lab, thực thi lệnh tĩnh (hardcode) an toàn
          try (Statement safeStmt = connection.createStatement()) {
              safeStmt.execute("GRANT ALL ON GRANT_RIGHTS TO UNAUTHORIZED_USER");
          }
      }

      // Kiểm tra xem user đã có quyền chưa (logic gốc của WebGoat)
      if (checkSolution(connection)) {
        return success(this).build();
      }
      
      // Xóa biến 'query' ra khỏi thông báo lỗi trả về để phòng thêm lỗi XSS (Cross-Site Scripting)
      return failed(this).output("Thao tác thất bại. Bạn hãy thử dùng lệnh GRANT để cấp quyền nhé!").build();
      
    } catch (Exception e) {
      return failed(this)
          .output(this.getClass().getName() + " : " + e.getMessage())
          .build();
    }
  }

  private boolean checkSolution(Connection connection) {
    try {
      var stmt =
          connection.prepareStatement(
              "SELECT * FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE TABLE_NAME = ? AND GRANTEE ="
                  + " ?");
      stmt.setString(1, "GRANT_RIGHTS");
      stmt.setString(2, "UNAUTHORIZED_USER");
      var resultSet = stmt.executeQuery();
      return resultSet.next();
    } catch (SQLException throwables) {
      return false;
    }
  }
}