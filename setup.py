from app import init_db, migrate_db, seed_initial_faqs  # make sure these are defined in app.py or imported from there

if __name__ == '__main__':
    init_db()
    print("✅ Database initialization completed")

    try:
        migrate_db()
        print("✅ Database migration completed successfully")
    except Exception as e:
        print(f"❌ Database migration error: {str(e)}")

    try:
        seed_initial_faqs()
        print("✅ Initial FAQs seeded successfully")
    except Exception as e:
        print(f"❌ Error seeding FAQs: {str(e)}")
