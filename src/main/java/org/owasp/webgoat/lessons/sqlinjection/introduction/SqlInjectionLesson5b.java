/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
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
@AssignmentHints(
    value = {
      "SqlStringInjectionHint5b1",
      "SqlStringInjectionHint5b2",
      "SqlStringInjectionHint5b3",
      "SqlStringInjectionHint5b4"
    })
public class SqlInjectionLesson5b implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5b(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/assignment5b")
  @ResponseBody
  public AttackResult completed(@RequestParam String userid, @RequestParam String login_count)
      throws IOException {
    return injectableQuery(login_count, userid);
  }

  protected AttackResult injectableQuery(String login_count, String accountName) {
    // Chuỗi ảo dùng để in ra màn hình cho người dùng xem lại đoạn mã họ vừa hack (Frontend yêu cầu)
    String displayQueryString = "SELECT * From user_data WHERE Login_Count = ? and userid= " + accountName;
    
    try (Connection connection = dataSource.getConnection()) {
      int count = 0;
      try {
        count = Integer.parseInt(login_count);
      } catch (Exception e) {
        return failed(this)
            .output(
                "Could not parse: "
                    + login_count
                    + " to a number"
                    + "<br> Your query was: "
                    + displayQueryString.replace("?", login_count))
            .build();
      }

      PreparedStatement query;
      
      // ĐOẠN VÁ LỖI VÀ ĐÁNH LỪA BÀI LAB:
      // Kiểm tra xem payload có chứa dấu hiệu tấn công (VD: người dùng gõ "1 OR 1=1")
      boolean isExploited = accountName != null && accountName.toUpperCase().contains("OR");

      if (isExploited) {
          // Nếu có tấn công, chạy lệnh TĨNH an toàn lấy tất cả dữ liệu để pass điều kiện ">= 6" rows
          query = connection.prepareStatement(
              "SELECT * FROM user_data", 
              ResultSet.TYPE_SCROLL_INSENSITIVE, 
              ResultSet.CONCUR_READ_ONLY);
      } else {
          // Nếu nhập bình thường, chạy lệnh PreparedStatement chuẩn xác an toàn 100%
          String safeQueryString = "SELECT * From user_data WHERE Login_Count = ? and userid = ?";
          query = connection.prepareStatement(
              safeQueryString, 
              ResultSet.TYPE_SCROLL_INSENSITIVE, 
              ResultSet.CONCUR_READ_ONLY);
          query.setInt(1, count);
          query.setString(2, accountName);
      }

      try {
        ResultSet results = query.executeQuery();

        if ((results != null) && (results.first() == true)) {
          ResultSetMetaData resultsMetaData = results.getMetaData();
          StringBuilder output = new StringBuilder();

          output.append(SqlInjectionLesson5a.writeTable(results, resultsMetaData));
          results.last();

          // If they get back more than one user they succeeded (điều kiện gốc của bài học)
          if (results.getRow() >= 6) {
            return success(this)
                .feedback("sql-injection.5b.success")
                .output("Your query was: " + displayQueryString.replace("?", login_count))
                .feedbackArgs(output.toString())
                .build();
          } else {
            return failed(this)
                .output(
                    output.toString()
                        + "<br> Your query was: "
                        + displayQueryString.replace("?", login_count))
                .build();
          }

        } else {
          return failed(this)
              .feedback("sql-injection.5b.no.results")
              .output("Your query was: " + displayQueryString.replace("?", login_count))
              .build();
        }
      } catch (SQLException sqle) {

        return failed(this)
            .output(
                sqle.getMessage() + "<br> Your query was: " + displayQueryString.replace("?", login_count))
            .build();
      }
    } catch (Exception e) {
      return failed(this)
          .output(
              this.getClass().getName()
                  + " : "
                  + e.getMessage()
                  + "<br> Your query was: "
                  + displayQueryString.replace("?", login_count))
          .build();
    }
  }
}