class FinancialTransformer:

    @staticmethod
    def income_band(income):

        bands = [
            (0, 20000, "Below ₹20,000"),
            (20000, 40000, "₹20,000–₹40,000"),
            (40000, 60000, "₹40,000–₹60,000"),
            (60000, 100000, "₹60,000–₹1,00,000"),
            (100000, 200000, "₹1,00,000–₹2,00,000"),
            (200000, float("inf"), "Above ₹2,00,000")
        ]

        for lower, upper, label in bands:
            if lower <= income < upper:
                return label

        return "Unknown"

    @staticmethod
    def age_band(age):

        if age < 0:
            return "Unknown"

        lower = (age // 5) * 5
        upper = lower + 4

        return f"{lower}–{upper} years"

    @staticmethod
    def emi_to_income_ratio(emi, income):

        if income <= 0:
            return None

        ratio = (emi / income) * 100

        return round(ratio, 2)

    @staticmethod
    def transform(entity_type, value):

        entity_type = entity_type.upper()

        try:
            if entity_type == "INCOME":
                return FinancialTransformer.income_band(
                    float(value)
                )

            if entity_type == "AGE":
                return FinancialTransformer.age_band(
                    int(value)
                )

        except (ValueError, TypeError):
            return "Unknown"

        return value