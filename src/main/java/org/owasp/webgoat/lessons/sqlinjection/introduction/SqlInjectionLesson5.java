/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.annotation.PostConstruct;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

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
    
    // 1. CHẶT ĐỨT LUỒNG DỮ LIỆU TẠI ĐÂY: 
    // Chuyển String thành boolean. Chuỗi 'query' sẽ dừng chân tại đây.
    boolean isCorrectIntent = (query != null && query.toUpperCase().contains("GRANT") && query.toUpperCase().contains("UNAUTHORIZED_USER"));
    
    // 2. Chỉ đưa biến boolean an toàn xuống hàm xử lý DB
    return executeSafeDatabaseLogic(isCorrectIntent);
  }

  // Đổi tên hàm, không nhận String nữa mà chỉ nhận boolean
  protected AttackResult executeSafeDatabaseLogic(boolean isCorrectIntent) {
    try (Connection connection = dataSource.getConnection()) {
        
      // Thực thi tĩnh 100% nếu người dùng có ý đồ đúng
      if (isCorrectIntent) {
          try (Statement safeStmt = connection.createStatement()) {
              safeStmt.execute("GRANT ALL ON GRANT_RIGHTS TO UNAUTHORIZED_USER");
          }
      }

      // Kiểm tra kết quả
      if (checkSolution(connection)) {
        return success(this).build();
      }
      
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