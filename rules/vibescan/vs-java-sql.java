import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.RequestParam;
import jakarta.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;

class SearchController {
    private JdbcTemplate jdbcTemplate;

    void fieldQuery(@RequestParam(name = "id") String id) {
        // ruleid: vs-java-sql
        jdbcTemplate.update("DELETE FROM items WHERE id = " + id);
        id = "42";
        // ok: vs-java-sql
        jdbcTemplate.update("DELETE FROM items WHERE id = " + id);
    }

    void search(@RequestParam("name") String name, JdbcTemplate jdbc) {
        String sql = "SELECT id FROM items WHERE name = '" + name + "'";
        // ruleid: vs-java-sql
        jdbc.queryForList(sql);
        // ok: vs-java-sql
        jdbc.queryForList("SELECT id FROM items WHERE name = ?", name);
    }

    void search(@RequestParam String name, Connection db) throws Exception {
        // ruleid: vs-java-sql
        db.prepareStatement("SELECT id FROM items WHERE name = '" + name + "'");
        // ok: vs-java-sql
        db.prepareStatement("SELECT id FROM items WHERE name = ?").setString(1, name);
    }

    void search(HttpServletRequest req, Statement statement) throws Exception {
        String name = req.getParameter("name");
        // ruleid: vs-java-sql
        statement.executeQuery("SELECT id FROM items WHERE name = '" + name + "'");
        // ok: vs-java-sql
        statement.executeQuery("SELECT id FROM items");
    }
}
