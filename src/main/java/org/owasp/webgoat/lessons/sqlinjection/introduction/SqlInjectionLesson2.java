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
      "SqlStringInjectionHint2-1",
      "SqlStringInjectionHint2-2",
      "SqlStringInjectionHint2-3",
      "SqlStringInjectionHint2-4"
    })
public class SqlInjectionLesson2 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson2(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  // THAY ĐỔI THIẾT KẾ: Nhận tên phòng ban (departmentName) thay vì cả câu lệnh SQL
  @PostMapping("/SqlInjection/attack2")
  @ResponseBody
  public AttackResult completed(@RequestParam String departmentName) {
    return injectableQuery(departmentName);
  }

  protected AttackResult injectableQuery(String departmentName) {
    
    // 1. Chuẩn bị câu lệnh SQL tĩnh với dấu chấm hỏi (?) làm tham số
    String safeQuery = "SELECT * FROM employees WHERE department = ?";

    // 2. Sử dụng Try-with-resources để tự động đóng Connection
    try (Connection connection = dataSource.getConnection();
         // 3. Sử dụng PreparedStatement thay vì Statement
         PreparedStatement pstmt = connection.prepareStatement(safeQuery, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {

      // 4. Gắn giá trị của người dùng vào dấu chấm hỏi (?).
      // Tại bước này, ký tự đặc biệt như ' hoặc " sẽ bị vô hiệu hóa (escape), không thể bẻ gãy câu lệnh.
      pstmt.setString(1, departmentName);

      // 5. Thực thi câu lệnh (Bọc ResultSet trong Try-with-resources để tránh rò rỉ)
      try (ResultSet results = pstmt.executeQuery()) {
        StringBuilder output = new StringBuilder();

        if (results.first()) {
            if (results.getString("department").equals("Marketing")) {
              output.append("<span class='feedback-positive'> Đã truy vấn phòng: " + departmentName + "</span>");
              output.append(SqlInjectionLesson8.generateTable(results));
              return success(this).feedback("sql-injection.2.success").output(output.toString()).build();
            } else {
              return failed(this).feedback("sql-injection.2.failed").output(output.toString()).build();
            }
        } else {
            return failed(this).feedback("sql-injection.2.failed").output("Không tìm thấy dữ liệu").build();
        }
      }
    } catch (SQLException sqle) {
      return failed(this).feedback("sql-injection.2.failed").output(sqle.getMessage()).build();
    }
  }
}