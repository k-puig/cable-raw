package com.kpuig.cable.server.api;

import java.sql.*;

public class CableServerDB {
    Connection sqliteConnection;

    // Completely erases all data in cable.db and recreates the tables
    public void initializeDB() throws SQLException {
        sqliteConnection = DriverManager.getConnection("jdbc:sqlite:cable.db");
        
    }
}
