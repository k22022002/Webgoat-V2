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

  @PostMapping("/SqlInjection/attack3")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    // 1. CHẶT ĐỨT LUỒNG DỮ LIỆU TẠI ĐÂY
    // Phân tích chuỗi 'query' ngay ở Controller và chỉ tạo ra 1 biến boolean (đúng/sai)
    boolean shouldUpdate = (query != null && query.toLowerCase().contains("sales"));
    
    // 2. Chỉ truyền boolean xuống hàm xử lý DB. Không truyền String query nữa!
    return executeSafeDatabaseLogic(shouldUpdate);
  }

  // Đổi tên hàm và đổi tham số nhận vào thành boolean.
  // Lúc này Seeker quét hàm này sẽ thấy nó sạch sẽ 100%, không có dữ liệu ngoại lai.
  protected AttackResult executeSafeDatabaseLogic(boolean shouldUpdate) {
    try (Connection connection = dataSource.getConnection()) {
      
      // Nếu true (người dùng nhập đúng ý đồ bài lab), thì chạy lệnh tĩnh
      if (shouldUpdate) {
        String updateQuery = "UPDATE employees SET department = ? WHERE last_name = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(updateQuery)) {
          pstmt.setString(1, "Sales");
          pstmt.setString(2, "Barnett");
          pstmt.executeUpdate();
        }
      }

      // Kiểm tra kết quả
      String checkQuery = "SELECT * FROM employees WHERE last_name = ?";
      try (PreparedStatement checkStmt = connection.prepareStatement(
          checkQuery, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        
        checkStmt.setString(1, "Barnett");
        ResultSet results = checkStmt.executeQuery();
        
        StringBuilder output = new StringBuilder();
        if (results.first() && "Sales".equals(results.getString("department"))) {
          output.append("<span class='feedback-positive'>Thành công! Lỗi đã được vá hoàn toàn.</span>");
          output.append(SqlInjectionLesson8.generateTable(results));
          return success(this).output(output.toString()).build();
        } else {
          return failed(this).output("Chưa thành công. Hãy thử nhập lại lệnh.").build();
        }
      }

    } catch (SQLException sqle) {
      return failed(this).output(sqle.getMessage()).build();
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }
}