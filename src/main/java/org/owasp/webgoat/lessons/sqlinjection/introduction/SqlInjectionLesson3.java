/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.PreparedStatement;
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
@AssignmentHints(value = {"SqlStringInjectionHint3-1", "SqlStringInjectionHint3-2"})
public class SqlInjectionLesson3 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson3(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

// 1. Endpoint giờ chỉ nhận dữ liệu cụ thể, không nhận nguyên câu lệnh SQL
  @PostMapping("/SqlInjection/attack3_secure")
  @ResponseBody
  public AttackResult completed(@RequestParam String newDepartment, @RequestParam String lastName) {
    return secureQuery(newDepartment, lastName);
  }

  protected AttackResult secureQuery(String newDepartment, String lastName) {
    // 2. Viết sẵn câu lệnh SQL an toàn với các dấu chấm hỏi (?)
    String updateQuery = "UPDATE employees SET department = ? WHERE last_name = ?";

    try (Connection connection = dataSource.getConnection()) {
      
      // 3. Khởi tạo PreparedStatement thay vì Statement thường
      try (PreparedStatement pstmt = connection.prepareStatement(updateQuery)) {
        
        // 4. Gán dữ liệu vào các tham số an toàn
        pstmt.setString(1, newDepartment);
        pstmt.setString(2, lastName);
        
        // 5. Thực thi câu lệnh đã được chuẩn bị
        pstmt.executeUpdate();

        // -------------------------------------------------------------
        // Phần code kiểm tra kết quả bên dưới để hoàn thành bài học
        // -------------------------------------------------------------
        Statement checkStatement = connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY);
        ResultSet results = checkStatement.executeQuery("SELECT * FROM employees WHERE last_name='Barnett';");
        
        StringBuilder output = new StringBuilder();
        results.first();
        if (results.getString("department").equals("Sales")) {
          output.append("<span class='feedback-positive'>Cập nhật thành công bằng PreparedStatement</span>");
          output.append(SqlInjectionLesson8.generateTable(results));
          return success(this).output(output.toString()).build();
        } else {
          return failed(this).output("Cập nhật không thành công.").build();
        }

      } catch (SQLException sqle) {
        return failed(this).output(sqle.getMessage()).build();
      }
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }
}
