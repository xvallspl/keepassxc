/*
 *  Copyright (C) 2021 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "SSHAdd.h"

#include "Utils.h"
#include "cli/TextStream.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Global.h"
#include "core/Group.h"
#include "sshagent/KeeAgentSettings.h"
#include "sshagent/SSHAgent.h"

#include <QCommandLineParser>
#include <QLocale>

const QCommandLineOption SSHAdd::ListOption =
    QCommandLineOption(QStringList() << "l", QObject::tr("List the SSH keys in the database."));
const QCommandLineOption SSHAdd::DeleteOption =
    QCommandLineOption(QStringList() << "d", QObject::tr("Remove the SSH keys from the agent instead of adding them."));

SSHAdd::SSHAdd()
{
    name = QString("ssh-add");
    description =
        QObject::tr("Add ssh keys from the database to the running SSH agent.");
    options.append(SSHAdd::ListOption);
    optionalArguments.append(
        {QString("entry"), QObject::tr("Name of the entry with an SSH key to unlock."), QString("")});
}

int SSHAdd::executeWithDatabase(QSharedPointer<Database> database, QSharedPointer<QCommandLineParser> parser)
{
    auto& out = Utils::STDOUT;
    auto& err = Utils::STDERR;

    const QStringList args = parser->positionalArguments();
    const QString& entryPath = args.at(1);
    bool listOption = parser->isSet(SSHAdd::ListOption);

    if (listOption) {
        // TODO raise an error or a warning if entryPath is defined.
        // TODO implement this.
        return EXIT_FAILURE;
    }

    if (entryPath.isNull()) {
        sshAgent()->databaseUnlocked(database);
        out << QObject::tr("Successfully added all the SSH keys to the SSH agent.") << endl;
        return EXIT_SUCCESS;
    }

    Entry* entry = database->rootGroup()->findEntryByPath(entryPath);
    if (!entry) {
        err << QObject::tr("Could not find entry with path %1.").arg(entryPath) << endl;
        return EXIT_FAILURE;
    }

    OpenSSHKey key;
    KeeAgentSettings settings;

    if (settings.toOpenSSHKey(entry, key, true)) {
        if (!settings.fromEntry(entry)) {
            return EXIT_FAILURE;
        }
        // @hifi: Should I check for the KeeAgent settings from the CLI?
        // if (!KeeAgentSettings::inEntryAttachments(currentEntry->attachments())) {
        // return EXIT_FAILURE;
        // }

        SSHAgent::instance()->addIdentity(key, settings, database->uuid());
        out << QObject::tr("Successfully added SSH key from entry %1 to the SSH agent.").arg(entryPath) << endl;
        return EXIT_SUCCESS;
    } else {
        err << QObject::tr("Error while adding  SSH key from entry %1 to the SSH agent: %2.")
                   .arg(entryPath, key.errorString())
            << endl;
        return EXIT_FAILURE;
    }
}
