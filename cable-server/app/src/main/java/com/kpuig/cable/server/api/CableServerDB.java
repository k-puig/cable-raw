package com.kpuig.cable.server.api;

import java.sql.*;

public class CableServerDB {
    Connection sqliteConnection;

    public void initializeDB() throws SQLException {
        sqliteConnection = DriverManager.getConnection("jdbc:sqlite:cable.db");
        
    }
}
