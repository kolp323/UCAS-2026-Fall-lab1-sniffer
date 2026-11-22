#pragma once
#include <QDialog>
#include <QHash>
#include <functional>

class QTableWidget;
class QLabel;
class QLineEdit;
class QTimer;

namespace lab1 {
// Each row represents one continuously observed local TCP endpoint pair.
class ProcessView : public QDialog {
public:
    using MatchPackets = std::function<void(const QString&)>;
    explicit ProcessView(QWidget* parent, MatchPackets match = {});
    ~ProcessView() override;
    void watch(quint32 pid);
private:
    void refresh();
    void stop(const QString& reason);
    void clearHistory();
    QTableWidget* table;
    QLineEdit* input;
    QLabel* status;
    QTimer* timer;
    void* process = nullptr;
    quint32 watchedPid = 0;
    QHash<QString,int> active;
};
}
