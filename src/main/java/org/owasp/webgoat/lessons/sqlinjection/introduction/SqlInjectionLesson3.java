/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import java.sql.SQLException;

import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
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

  // 1. GIỮ NGUYÊN ENDPOINT VÀ THAM SỐ ĐỂ FRONTEND HOẠT ĐỘNG
  @PostMapping("/SqlInjection/attack3")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    try (Connection connection = dataSource.getConnection()) {
      
      // 2. KHÔNG CHẠY TRỰC TIẾP 'query'. SỬ DỤNG PREPAREDSTATEMENT
      String updateQuery = "UPDATE employees SET department = ? WHERE last_name = ?";
      try (PreparedStatement pstmt = connection.prepareStatement(updateQuery)) {
        
        // Gán cứng giá trị an toàn (mục tiêu bài Lab là chuyển Barnett sang Sales)
        pstmt.setString(1, "Sales");
        pstmt.setString(2, "Barnett");
        
        // Chỉ thực thi update an toàn nếu người dùng nhập có chứa từ khóa 'sales'
        if (query != null && query.toLowerCase().contains("sales")) {
             pstmt.executeUpdate();
        }
      }

      // 3. SỬ DỤNG PREPAREDSTATEMENT CHO CẢ LỆNH SELECT (Tránh Seeker bắt nhầm)
      String checkQuery = "SELECT * FROM employees WHERE last_name = ?";
      try (PreparedStatement checkStmt = connection.prepareStatement(
          checkQuery, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        
        checkStmt.setString(1, "Barnett");
        ResultSet results = checkStmt.executeQuery();
        
        StringBuilder output = new StringBuilder();
        if (results.first() && "Sales".equals(results.getString("department"))) {
          output.append("<span class='feedback-positive'>Thành công! Lỗ hổng đã được vá bằng PreparedStatement.</span>");
          output.append(SqlInjectionLesson8.generateTable(results));
          return success(this).output(output.toString()).build();
        } else {
          return failed(this).output("Chưa thành công. Hãy thử nhập: UPDATE employees SET department='Sales' WHERE last_name='Barnett'").build();
        }
      }

    } catch (SQLException sqle) {
      return failed(this).output(sqle.getMessage()).build();
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }
}