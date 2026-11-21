#include "display_filter.h"

#include <QHostAddress>
#include <QRegularExpression>

namespace lab1 {
namespace {

class FilterParser {
public:
    explicit FilterParser(QString input) : text(std::move(input)) {}
    QString error;

    DisplayPredicate parse() {
        if (text.size() > 512) return invalid("Use at most 512 characters");
        if (text.trimmed().isEmpty()) return [](const Packet&) { return true; };
        auto result = disjunction(0);
        skip();
        if (result && pos != text.size()) return invalid("Unexpected text");
        return result;
    }

private:
    QString text;
    int pos = 0;

    DisplayPredicate invalid(const QString& reason) {
        if (error.isEmpty()) error = reason + QString(" at position %1").arg(pos + 1);
        return {};
    }

    void skip() {
        while (pos < text.size() && text[pos].isSpace()) ++pos;
    }

    bool consume(const QString& literal, bool keyword = false) {
        skip();
        if (text.midRef(pos, literal.size()).compare(literal, Qt::CaseInsensitive) != 0) return false;
        const int end = pos + literal.size();
        if (keyword && end < text.size() &&
            (text[end].isLetterOrNumber() || text[end] == '_' || text[end] == '.'))
            return false;
        pos = end;
        return true;
    }

    QString word() {
        skip();
        const int start = pos;
        while (pos < text.size() &&
               (text[pos].isLetterOrNumber() || QStringLiteral("_:.").contains(text[pos]))) ++pos;
        return text.mid(start, pos - start);
    }

    DisplayPredicate disjunction(int depth) {
        auto left = conjunction(depth);
        while (left && consume("OR", true)) {
            auto right = conjunction(depth);
            if (!right) return {};
            left = [left=std::move(left), right=std::move(right)](const Packet& p) {
                return left(p) || right(p);
            };
        }
        return left;
    }

    DisplayPredicate conjunction(int depth) {
        auto left = unary(depth);
        while (left && consume("AND", true)) {
            auto right = unary(depth);
            if (!right) return {};
            left = [left=std::move(left), right=std::move(right)](const Packet& p) {
                return left(p) && right(p);
            };
        }
        return left;
    }

    DisplayPredicate unary(int depth) {
        if (depth >= 24) return invalid("Expression nested too deeply");
        if (consume("NOT", true)) {
            auto operand = unary(depth + 1);
            if (!operand) return {};
            return [operand=std::move(operand)](const Packet& p) { return !operand(p); };
        }
        if (consume("(")) {
            auto result = disjunction(depth + 1);
            if (!result || !consume(")")) return invalid("Expected closing parenthesis");
            return result;
        }
        return predicate();
    }

    DisplayPredicate predicate() {
        const QString name = word().toLower();
        static const QStringList protocols = {
            "all", "ethernet", "ipv4", "ipv6", "tcp", "udp", "icmp", "icmpv6", "http"
        };
        if (protocols.contains(name)) {
            return [name](const Packet& p) { return matchesDisplayFilter(p, name); };
        }

        static const QStringList numbers = {
            "tcp.srcport", "tcp.dstport", "tcp.flags", "udp.srcport", "udp.dstport",
            "udp.length", "ip.version", "icmp.type", "icmp.code"
        };
        const bool isNumber = numbers.contains(name);
        const bool isStatus = name == "status";
        if (!isNumber && !isStatus && name != "src" && name != "dst")
            return invalid("Expected a protocol or known field");

        const bool unequal = consume("!=");
        if (!unequal && !consume("==")) return invalid("Expected == or !=");
        const QString value = word();
        if (isNumber) {
            static const QRegularExpression decimal("^[0-9]+$");
            bool ok = false;
            const uint number = value.toUInt(&ok);
            if (!ok || !decimal.match(value).hasMatch() || number > 65535)
                return invalid("Expected a decimal number in 0..65535");
            return [name, number, unequal](const Packet& p) {
                if (name == "ip.version")
                    return p.ipVersion > 0 && ((uint(p.ipVersion) == number) != unequal);
                for (const auto& field : p.fields)
                    if (field.name == name) return (field.value.toUInt() == number) != unequal;
                return false;
            };
        }
        if (isStatus) {
            const QString state = value.toLower();
            if (!QStringList{"valid", "truncated", "malformed", "unsupported", "fragment"}.contains(state))
                return invalid("Unknown packet status");
            return [state, unequal](const Packet& p) { return (p.status == state) != unequal; };
        }
        const QHostAddress address(value);
        if (address.isNull()) return invalid("Expected a literal IP address");
        return [name, address, unequal](const Packet& p) {
            const QHostAddress found(name == "src" ? p.src : p.dst);
            return !found.isNull() && (found.isEqual(address, QHostAddress::StrictConversion) != unequal);
        };
    }
};

}

DisplayPredicate compileDisplayFilter(const QString& expression, QString& error) {
    FilterParser parser(expression);
    auto filter = parser.parse();
    error = parser.error;
    return filter;
}
}

