import React from 'react';
import { Bot, User } from 'lucide-react';

const ChatMessage = ({ message }) => {
  const { text, sender, timestamp } = message;
  const isUser = sender === 'user';
  const isSystem = sender === 'system';

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (isSystem) {
    return (
      <div className="flex justify-center my-4">
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg px-4 py-2 max-w-md">
          <p className="text-yellow-800 text-sm text-center">{text}</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'} mb-4`}>
      <div className={`flex items-start space-x-2 max-w-xs lg:max-w-md ${isUser ? 'flex-row-reverse space-x-reverse' : ''}`}>
        <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${isUser ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-600'
          }`}>
          {isUser ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4" />}
        </div>

        <div className={`rounded-lg px-4 py-2 ${isUser
            ? 'bg-blue-600 text-white'
            : 'bg-white border border-gray-200 text-gray-800'
          }`}>
          <p className="text-sm">{text}</p>
          <p className={`text-xs mt-1 ${isUser ? 'text-blue-100' : 'text-gray-500'}`}>
            {formatTime(timestamp)}
          </p>
        </div>
      </div>
    </div>
  );
};

export default ChatMessage;