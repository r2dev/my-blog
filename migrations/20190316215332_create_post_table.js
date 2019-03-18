exports.up = function(knex, Promise) {
  return knex.schema.createTable("post", table => {
    table.increments();
    table.string("title");
    table.string("content");
    table.string("parsed_content");
    table
      .integer("author")
      .unsigned()
      .notNullable();
    table.timestamp("created_at");
    table
      .foreign("author")
      .references("id")
      .inTable("user");
  });
};

exports.down = function(knex, Promise) {
  return knex.schema.dropTable("post");
};
